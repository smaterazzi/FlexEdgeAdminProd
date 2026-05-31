"""
FlexEdgeAdmin — Database initialization on first run.

Called during app startup:
  1. Generates the encryption key file if it doesn't exist
  2. Creates database tables if they don't exist
  3. Sets a flag indicating whether the setup wizard is needed
  4. Runs lightweight ALTER TABLE migrations for the small set of additive
     schema changes the project has accumulated (no formal migration framework).
"""

import logging
import os
import re
import shutil
from datetime import datetime, timezone

from shared.encryption import key_file_exists, generate_key_file, load_key, KEY_FILE

log = logging.getLogger(__name__)


def _create_all_with_race_retry(db):
    """Run db.create_all() with first-boot worker-race tolerance.

    The bug: gunicorn under `-w 2` (no `--preload`) imports the app
    independently in each worker. Both workers reach `db.create_all()`
    at roughly the same time. SQLAlchemy's `checkfirst=True` does a
    `SELECT FROM sqlite_master` per worker, but that SELECT is NOT
    atomic with the subsequent `CREATE TABLE`. The classic TOCTOU race:

        Worker A: SELECT — no smc_objects → CREATE → commits
        Worker B: SELECT — no smc_objects → CREATE → BOOM
                  ("table already exists")

    Existing tables don't trip this because they sit in sqlite_master
    from a previous boot — checkfirst sees them. Only freshly added
    tables hit the race during their FIRST boot.

    Fix: catch the "already exists" error, log, and re-run create_all.
    The retry's checkfirst now sees the loser-worker's CREATE committed
    by the winner, treats every table as existing, and short-circuits.

    The Dockerfile also passes `--preload` to gunicorn so this race
    never happens in production — but this defensive retry catches it
    for any non-preloaded deployment (e.g. dev `flask run`, single
    `python webapp/app.py`, future multi-instance deployments).
    """
    from sqlalchemy.exc import OperationalError, ProgrammingError
    try:
        db.create_all()
        return
    except (OperationalError, ProgrammingError) as exc:
        msg = str(exc).lower()
        if "already exists" not in msg:
            raise
        log.warning("create_all hit a worker-race 'already exists' error — "
                    "another worker beat us to it. Retrying with checkfirst.")
        try:
            db.session.rollback()
        except Exception:
            pass

    # Retry once. By now the winner committed; checkfirst should see every
    # table as existing and short-circuit. If THIS still races (extremely
    # unlikely), surface the error.
    db.create_all()


def _enable_sqlite_foreign_keys(app):
    """Set per-connection SQLite pragmas: foreign_keys, busy_timeout, synchronous.

    SQLite ships with FK enforcement DISABLED by default — declared FKs
    are documentation only unless the connection sets the pragma.
    Without this, deleting a parent row (e.g. a Tenant) silently leaves
    child rows pointing at a non-existent id, and inserting a child row
    with a bogus parent id slips through. We hit exactly that during
    the multi-domain wipe + re-create on 2026-04-29.

    busy_timeout=5000: default is 0, meaning a contended writer raises
    `OperationalError: database is locked` instantly. 5s is enough to ride
    out queue runner pushes / drift scans / boot-time migrations colliding
    with operator clicks (audit H1, 2026-05-09).

    synchronous=NORMAL: WAL-mode safe and ~3x faster than the FULL default
    that SQLite uses out of the box. NORMAL still sync's at the WAL
    checkpoint boundary, so a power-loss only loses the last in-flight
    transaction (acceptable for an admin tool).

    Registers a SQLAlchemy `connect` event listener that runs the pragmas
    against the actual SQLite DBAPI connection.
    """
    if "sqlite" not in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
        return
    from shared.db import db
    from sqlalchemy import event

    @event.listens_for(db.engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()


def init_database(app):
    """Initialize encryption key and database tables.

    Call this after db.init_app(app) in the Flask app setup.
    Sets app.config["SETUP_REQUIRED"] = True if no users exist yet.
    """
    from shared.db import db

    key_path = os.environ.get("ENCRYPTION_KEY_FILE", KEY_FILE)

    # 1. Ensure encryption key exists
    if not key_file_exists(key_path):
        generate_key_file(key_path)
        log.info("Generated new encryption key at %s", key_path)
    else:
        load_key(key_path)  # Validate the key loads correctly
        log.debug("Encryption key loaded from %s", key_path)

    # 2. Create DB tables if they don't exist
    with app.app_context():
        # Import models so they are registered with SQLAlchemy
        import webapp.models  # noqa: F401
        # Register FK-enforcement listener BEFORE the first connection is
        # made so every connection (including the one create_all uses)
        # has the pragma applied.
        _enable_sqlite_foreign_keys(app)
        _migrate_pre_create(db, app)
        _create_all_with_race_retry(db)
        _migrate_post_create(db, app)
        log.info("Database tables ensured at %s", app.config["SQLALCHEMY_DATABASE_URI"])

    # 3. Check if setup wizard is needed (no users in DB AND no sentinel).
    #    H10 (audit fix-up, 2026-05-09): the `setup_completed` row in
    #    `platform_settings` is dropped by the wizard on success and acts
    #    as a tamper-resistant marker — deleting User rows manually does
    #    NOT re-arm the wizard, because the sentinel still says setup ran.
    with app.app_context():
        from webapp.models import User, PlatformSetting
        user_count = User.query.count()
        sentinel = db.session.get(PlatformSetting, "setup_completed")
        app.config["SETUP_REQUIRED"] = (user_count == 0 and sentinel is None)
        if app.config["SETUP_REQUIRED"]:
            log.warning("No users in database — setup wizard will be shown on first visit")
        elif user_count == 0 and sentinel is not None:
            log.warning(
                "Setup sentinel present but no users — setup wizard will "
                "NOT re-arm. Restore from backup or delete the "
                "`setup_completed` row in platform_settings to recover."
            )


def is_setup_required(app) -> bool:
    """Check whether the setup wizard still needs to run."""
    return app.config.get("SETUP_REQUIRED", False)


# ── Lightweight migration helpers ────────────────────────────────────────
# Used in lieu of a formal migration framework — only handles the small set
# of additive / one-shot schema changes the project has accumulated.

def _sqlite_columns(db, table: str) -> list[str]:
    """Return the column names of a SQLite table; empty list if no table."""
    try:
        rows = db.session.execute(db.text(f"PRAGMA table_info({table})")).all()
        return [row[1] for row in rows]
    except Exception:
        return []


def _is_sqlite(app) -> bool:
    return "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", "")


def _migrate_pre_create(db, app):
    """Run BEFORE db.create_all() — handles destructive changes
    (drop-and-recreate) so create_all rebuilds the table fresh.
    """
    if not _is_sqlite(app):
        return  # Non-SQLite: assume a real DBA handles it.

    cols = _sqlite_columns(db, "dhcp_engine_credentials")
    if cols and ("private_key_pem" in cols or "public_key_openssh" in cols):
        log.warning(
            "Detected legacy key-based dhcp_engine_credentials schema; "
            "dropping table — credentials will need re-enrollment."
        )
        try:
            db.session.execute(db.text("DROP TABLE dhcp_engine_credentials"))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to drop legacy dhcp_engine_credentials: %s", exc)


def _migrate_post_create(db, app):
    """Run AFTER db.create_all() — handles additive changes that create_all
    won't apply to an EXISTING table (it only creates *missing* tables).
    """
    if not _is_sqlite(app):
        return

    # Add tenants.flexedge_source_ip if missing (existing tenants tables
    # predate this column).
    cols = _sqlite_columns(db, "tenants")
    if cols and "flexedge_source_ip" not in cols:
        log.info("Adding tenants.flexedge_source_ip column")
        try:
            db.session.execute(db.text(
                "ALTER TABLE tenants ADD COLUMN flexedge_source_ip "
                "VARCHAR(45) NOT NULL DEFAULT ''"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add tenants.flexedge_source_ip: %s", exc)

    # Add dhcp_reservations.source if missing (FortiGate-migration origin tag)
    cols = _sqlite_columns(db, "dhcp_reservations")
    if cols and "source" not in cols:
        log.info("Adding dhcp_reservations.source column")
        try:
            db.session.execute(db.text(
                "ALTER TABLE dhcp_reservations ADD COLUMN source "
                "VARCHAR(64) NOT NULL DEFAULT ''"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add dhcp_reservations.source: %s", exc)

    # Phase E.2 — add dhcp_reservations.pending_change_id (nullable FK to
    # pending_changes.id). Links a reservation row to the queue entry that
    # controls it when status ∈ ('queued', 'push_failed'); NULL otherwise.
    # Cleared on successful push.
    cols = _sqlite_columns(db, "dhcp_reservations")
    if cols and "pending_change_id" not in cols:
        log.info("Phase E.2: ALTER dhcp_reservations ADD COLUMN pending_change_id")
        try:
            db.session.execute(db.text(
                "ALTER TABLE dhcp_reservations ADD COLUMN "
                "pending_change_id INTEGER NULL "
                "REFERENCES pending_changes(id) ON DELETE SET NULL"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add dhcp_reservations.pending_change_id: %s", exc)

    # Add dhcp_deployments.reload_warning if missing — split from `error`
    # so the audit log can distinguish "wrote nothing" from "wrote but
    # could not reload dhcpd". Existing deployments may have the warning
    # text in `error`; we leave those rows alone (operator-readable, and
    # the column is also populated going forward).
    cols = _sqlite_columns(db, "dhcp_deployments")
    if cols and "reload_warning" not in cols:
        log.info("Adding dhcp_deployments.reload_warning column")
        try:
            db.session.execute(db.text(
                "ALTER TABLE dhcp_deployments ADD COLUMN reload_warning "
                "TEXT NOT NULL DEFAULT ''"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add dhcp_deployments.reload_warning: %s", exc)

    # Add state_refreshed_at to credential + access tables. Drives the
    # 24h cache-freshness UX on the credentials page. Existing rows are
    # backfilled from last_verified_at / created_at so they show a
    # sensible baseline rather than appearing "never refreshed".
    cols = _sqlite_columns(db, "dhcp_engine_credentials")
    if cols and "state_refreshed_at" not in cols:
        log.info("Adding dhcp_engine_credentials.state_refreshed_at column")
        try:
            db.session.execute(db.text(
                "ALTER TABLE dhcp_engine_credentials ADD COLUMN "
                "state_refreshed_at DATETIME NULL"
            ))
            db.session.execute(db.text(
                "UPDATE dhcp_engine_credentials "
                "SET state_refreshed_at = COALESCE(last_verified_at, created_at) "
                "WHERE state_refreshed_at IS NULL"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add dhcp_engine_credentials.state_refreshed_at: %s", exc)

    cols = _sqlite_columns(db, "dhcp_engine_ssh_access")
    if cols and "state_refreshed_at" not in cols:
        log.info("Adding dhcp_engine_ssh_access.state_refreshed_at column")
        try:
            db.session.execute(db.text(
                "ALTER TABLE dhcp_engine_ssh_access ADD COLUMN "
                "state_refreshed_at DATETIME NULL"
            ))
            db.session.execute(db.text(
                "UPDATE dhcp_engine_ssh_access "
                "SET state_refreshed_at = COALESCE(last_seen_in_policy_at, created_at) "
                "WHERE state_refreshed_at IS NULL"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add dhcp_engine_ssh_access.state_refreshed_at: %s", exc)

    # P1 — contact-address-aware connect IP (2026-05-12). NULL/empty
    # preserves today's behavior (dial `hostname` directly); set per-row
    # via the credentials wizard when a node sits behind 1:1 NAT and
    # FEA needs to reach its public exit address.
    cols = _sqlite_columns(db, "dhcp_engine_credentials")
    if cols and "connect_ip_override" not in cols:
        log.info("P1: ALTER dhcp_engine_credentials ADD COLUMN connect_ip_override")
        try:
            db.session.execute(db.text(
                "ALTER TABLE dhcp_engine_credentials ADD COLUMN "
                "connect_ip_override TEXT NOT NULL DEFAULT ''"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add dhcp_engine_credentials.connect_ip_override: %s", exc)

    # Phase G — drift detector. Adds `drift_state`, `last_drift_check_at`,
    # `drift_detail` columns to smc_objects. Pre-existing rows get a default
    # of 'unknown' and become 'clean' on the first scan that successfully
    # fetches them from SMC.
    cols = _sqlite_columns(db, "smc_objects")
    if cols and "drift_state" not in cols:
        log.info("Phase G: ALTER smc_objects ADD COLUMN drift_state")
        try:
            db.session.execute(db.text(
                "ALTER TABLE smc_objects ADD COLUMN drift_state "
                "VARCHAR(16) NOT NULL DEFAULT 'unknown'"
            ))
            db.session.execute(db.text(
                "ALTER TABLE smc_objects ADD COLUMN last_drift_check_at "
                "DATETIME NULL"
            ))
            db.session.execute(db.text(
                "ALTER TABLE smc_objects ADD COLUMN drift_detail "
                "VARCHAR(512) NOT NULL DEFAULT ''"
            ))
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Failed to add Phase G drift columns: %s", exc)

    # Multi-Domain Revamp — Phase A. Idempotent: returns immediately if the
    # api_keys table already has the new columns, meaning Phase A ran on
    # a previous boot.
    _phase_a_multidomain(db, app)

    # Phase B.1 — adds domain_id to every feature table and backfills it
    # from (tenant_id, api_key_id) → Domain. Idempotent.
    _phase_b1_feature_domain_ids(db, app)

    # Platform-log unification — backfills platform_logs from the legacy
    # per-feature activity tables. Idempotent: tracked via a marker row in
    # platform_settings so it never re-runs.
    _phase_log_unification(db, app)

    # Change Management — Phase A (refined 2026-05-01 to four-tier model).
    # Brings up `users.is_super_admin` (renaming the earlier
    # `users.is_global_admin` if present) and `user_domain_access.role`,
    # then backfills:
    #   * lowest-id legacy admin → is_super_admin=True (sees every Domain)
    #   * other legacy admins (multi-admin envs) → demoted to per-Domain
    #     UserDomainAccess.role='global_admin' on every Domain they had
    #     access to (preserves their power within those Domains).
    # The new smc_objects + pending_changes tables are created empty by
    # db.create_all() above; this migration only handles the additive
    # role columns + backfill. Idempotent.
    _phase_change_mgmt_a(db, app)

    # M8 (audit fix-up, 2026-05-09): composite index on (domain_id, timestamp)
    # for `platform_logs`. db.create_all() picks it up on fresh installs;
    # existing DBs need an explicit `CREATE INDEX IF NOT EXISTS`.
    _phase_audit_indexes(db, app)

    # Roadmap item 5 — Let's Encrypt CRUD (Phase LE.1, 2026-05-11):
    # extend `managed_certificates` with the FEA-driven request lifecycle.
    # The two new tables `acme_accounts` and `domain_cert_patterns` are
    # created empty by `db.create_all()` above; this phase only handles
    # additive column adds on the existing `managed_certificates` table.
    _phase_le_certs(db, app)

    # Audit V1 (2026-05-29): one-shot move of pre-V1 migration projects
    # from `webapp/projects/` into the resolved `PROJECTS_DIR` (typically
    # `/app/data/projects/` in Docker). Idempotent — see the helper for
    # the gate conditions. Pure filesystem op, runs outside the DB
    # transaction; failures log + swallow, never abort boot.
    try:
        from webapp import project_manager
        project_manager._migrate_legacy_projects_dir()
    except Exception as exc:
        log.warning("V1 legacy-projects migration skipped: %s", exc)


def _phase_le_certs(db, app):
    """Extend `managed_certificates` for the Let's Encrypt CRUD feature.

    Idempotent: each column add is guarded by a `PRAGMA table_info`
    lookup so subsequent boots skip them. Existing rows (legacy
    operator-tracked certs that pointed at pre-existing certbot output)
    get sensible defaults — `status='active'` because if they're
    already in the DB they're already deployed; `is_staging=False`;
    everything else NULL.

    Phase LE.1 schema, 2026-05-11.
    """
    if not _is_sqlite(app):
        return
    cols = _sqlite_columns(db, "managed_certificates")
    if not cols:
        # Table doesn't exist yet — fresh install. `db.create_all()` will
        # land the full new schema; nothing for this phase to do.
        return
    additions = [
        # (column_name, ALTER TABLE fragment)
        ("domain_id",
         "ALTER TABLE managed_certificates ADD COLUMN domain_id INTEGER REFERENCES domains(id) ON DELETE SET NULL"),
        ("requested_by_user_id",
         "ALTER TABLE managed_certificates ADD COLUMN requested_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"),
        ("status",
         "ALTER TABLE managed_certificates ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'active'"),
        ("last_error",
         "ALTER TABLE managed_certificates ADD COLUMN last_error TEXT NOT NULL DEFAULT ''"),
        ("is_staging",
         "ALTER TABLE managed_certificates ADD COLUMN is_staging BOOLEAN NOT NULL DEFAULT 0"),
        ("pending_change_id",
         "ALTER TABLE managed_certificates ADD COLUMN pending_change_id INTEGER REFERENCES pending_changes(id) ON DELETE SET NULL"),
        ("next_renewal_after",
         "ALTER TABLE managed_certificates ADD COLUMN next_renewal_after DATETIME"),
        ("account_id",
         "ALTER TABLE managed_certificates ADD COLUMN account_id INTEGER REFERENCES acme_accounts(id) ON DELETE SET NULL"),
        ("challenge_type",
         "ALTER TABLE managed_certificates ADD COLUMN challenge_type VARCHAR(16) NOT NULL DEFAULT 'http01'"),
        ("dns_challenge_state",
         "ALTER TABLE managed_certificates ADD COLUMN dns_challenge_state VARCHAR(16)"),
        ("dns_challenge_record_name",
         "ALTER TABLE managed_certificates ADD COLUMN dns_challenge_record_name VARCHAR(512)"),
        ("dns_challenge_record_value",
         "ALTER TABLE managed_certificates ADD COLUMN dns_challenge_record_value VARCHAR(512)"),
    ]
    added = []
    for col_name, sql in additions:
        if col_name in cols:
            continue
        try:
            db.session.execute(db.text(sql))
            db.session.commit()
            added.append(col_name)
        except Exception as exc:
            log.warning("LE.1: failed to add managed_certificates.%s (non-fatal): %s",
                        col_name, exc)
            try:
                db.session.rollback()
            except Exception:
                pass
    if added:
        log.info("LE.1: added managed_certificates columns: %s",
                 ", ".join(added))
    # Index on next_renewal_after so the renewal scheduler's "due soon"
    # query (Phase LE.3) is cheap.
    try:
        db.session.execute(db.text(
            "CREATE INDEX IF NOT EXISTS ix_managed_certificates_next_renewal "
            "ON managed_certificates (next_renewal_after)"
        ))
        db.session.commit()
    except Exception as exc:
        log.warning("LE.1: renewal index create failed (non-fatal): %s", exc)
        try:
            db.session.rollback()
        except Exception:
            pass


def _phase_audit_indexes(db, app):
    """Add audit-driven indexes on existing tables. Idempotent.

    Currently:
      * `ix_platform_logs_domain_ts` on `platform_logs(domain_id, timestamp)`
        — drives the /logs viewer. SQLite's `CREATE INDEX IF NOT EXISTS`
        is a no-op when the index already exists, so this is safe to run
        on every boot.
    """
    if not _is_sqlite(app):
        return
    try:
        db.session.execute(db.text(
            "CREATE INDEX IF NOT EXISTS ix_platform_logs_domain_ts "
            "ON platform_logs (domain_id, timestamp)"
        ))
        db.session.commit()
    except Exception as exc:
        log.warning("M8: composite log index creation failed (non-fatal): %s",
                    exc)
        try:
            db.session.rollback()
        except Exception:
            pass


# ── Multi-Domain Revamp — Phase A ────────────────────────────────────────
#
# Brings the new schema online side-by-side with the legacy tables:
#   1. api_keys gains smc_url + verify_ssl + timeout + api_version + flexedge_source_ip
#      (all backfilled from the owning Tenant row).
#   2. The new `domains` table is created (by db.create_all() before this runs)
#      and gets one row per existing ApiKey using the tenant's default_domain.
#   3. `user_domain_access` is backfilled from `user_tenant_access`.
#
# Phase B (later) will drop tenants, user_tenant_access, and the redundant
# api_keys.tenant_id once every feature table is keyed by domain_id.

def _slugify(value: str, fallback: str = "domain") -> str:
    """Lowercase + dash-separated slug suitable for URL/CLI use."""
    s = (value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or fallback


def _backup_sqlite_db(app, suffix: str = "pre-multidomain") -> str | None:
    """Copy the SQLite DB to <name>.<suffix>-<UTCstamp>.bak. Returns the
    backup path, or None if the URI isn't a file-based sqlite. Best-effort
    — failure is logged but does NOT block the migration. Operators can
    always recover from their own backups in production.
    """
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if not uri.startswith("sqlite:///"):
        return None
    db_path = uri[len("sqlite:///"):]
    if not os.path.isfile(db_path):
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    backup_path = f"{db_path}.{suffix}-{ts}.bak"
    try:
        shutil.copy2(db_path, backup_path)
        log.warning("DB backed up to %s before destructive migration", backup_path)
        return backup_path
    except Exception as exc:
        log.error("Failed to back up DB before migration: %s", exc)
        return None


def _phase_a_multidomain(db, app):
    """Phase A of the Multi-Domain Revamp. See docs/MultiDomainRevamp.md.

    Sequence:
      1. Detect whether Phase A already ran. If so, return immediately.
      2. If `tenants` table is absent (fresh install) — nothing to migrate.
         The new schema is already what db.create_all() produced.
      3. Otherwise: backup, then ALTER api_keys + backfill server fields +
         INSERT domains rows + INSERT user_domain_access rows.
    """
    if not _is_sqlite(app):
        return  # Real DBA territory.

    api_cols = _sqlite_columns(db, "api_keys")
    if not api_cols:
        return  # No api_keys yet — fresh install before db.create_all even ran.

    if "smc_url" in api_cols:
        # Phase A already applied on a previous boot.
        return

    if "tenants" not in [t for t in _sqlite_tables(db)]:
        # Fresh install, no legacy data: just add the columns to api_keys
        # so the model + the actual schema agree. domains/user_domain_access
        # are already created (or empty) via db.create_all().
        log.info("Phase A: fresh DB detected — only adding new api_keys columns")
        try:
            _add_api_keys_columns(db)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            log.error("Phase A (fresh) failed: %s", exc)
        return

    # Real migration path: legacy tenants table exists, contains data.
    log.warning("Phase A: starting multi-domain migration "
                "(api_keys absorbs server fields, domains backfilled from tenants)")

    backup_path = _backup_sqlite_db(app, suffix="pre-multidomain")
    if backup_path:
        log.warning("Phase A: backup created at %s — keep it until you've "
                    "verified the migration", backup_path)

    try:
        # Step 1 — extend api_keys with the absorbed server-level columns.
        _add_api_keys_columns(db)

        # Step 2 — backfill the new columns from the owning tenant.
        # COALESCE on default_domain + api_version because they're optionally
        # blank in some tenants.
        db.session.execute(db.text("""
            UPDATE api_keys SET
                smc_url            = (SELECT smc_url FROM tenants WHERE tenants.id = api_keys.tenant_id),
                verify_ssl         = COALESCE((SELECT verify_ssl FROM tenants WHERE tenants.id = api_keys.tenant_id), 0),
                timeout            = COALESCE((SELECT timeout FROM tenants WHERE tenants.id = api_keys.tenant_id), 120),
                api_version        = (SELECT api_version FROM tenants WHERE tenants.id = api_keys.tenant_id),
                flexedge_source_ip = COALESCE((SELECT flexedge_source_ip FROM tenants WHERE tenants.id = api_keys.tenant_id), '')
            WHERE EXISTS (SELECT 1 FROM tenants WHERE tenants.id = api_keys.tenant_id)
        """))

        # Step 3 — create one Domain row per ApiKey. smc_domain_name comes
        # from the owning tenant's default_domain (fallback "Shared Domain"
        # when blank — that's SMC's literal default-domain name). Slug uses
        # the tenant slug so existing `--tenant <slug>` CLI invocations keep
        # resolving to the same Domain.
        rows = db.session.execute(db.text("""
            SELECT
              ak.id            AS api_key_id,
              ak.name          AS api_key_name,
              t.id             AS tenant_id,
              t.slug           AS tenant_slug,
              t.name           AS tenant_name,
              t.default_domain AS default_domain
            FROM api_keys ak
            JOIN tenants t ON t.id = ak.tenant_id
            WHERE ak.id NOT IN (SELECT api_key_id FROM domains)
        """)).all()

        used_slugs = {r[0] for r in db.session.execute(db.text(
            "SELECT slug FROM domains"
        )).all()}
        domains_created = 0
        for r in rows:
            api_key_id, api_key_name, tenant_id, tenant_slug, tenant_name, default_domain = r
            smc_domain = (default_domain or "").strip() or "Shared Domain"
            display_name = f"{tenant_name} · {smc_domain}"
            base_slug = _slugify(tenant_slug or tenant_name, fallback="domain")
            slug = base_slug
            n = 2
            while slug in used_slugs:
                slug = f"{base_slug}-{n}"
                n += 1
            used_slugs.add(slug)
            db.session.execute(db.text("""
                INSERT INTO domains (api_key_id, smc_domain_name, display_name, slug,
                                     is_active, created_at, updated_at)
                VALUES (:api_key_id, :smc_domain, :display_name, :slug,
                        1, :now, :now)
            """), {
                "api_key_id": api_key_id,
                "smc_domain": smc_domain,
                "display_name": display_name,
                "slug": slug,
                "now": datetime.now(timezone.utc),
            })
            domains_created += 1

        # Step 4 — backfill user_domain_access from user_tenant_access.
        # Match each access row to its derived Domain via api_key_id +
        # the tenant's default_domain.
        result = db.session.execute(db.text("""
            INSERT OR IGNORE INTO user_domain_access (user_id, domain_id, is_default, created_at)
            SELECT
              uta.user_id,
              d.id          AS domain_id,
              uta.is_default,
              :now
            FROM user_tenant_access uta
            JOIN tenants t ON t.id = uta.tenant_id
            JOIN domains d ON d.api_key_id = uta.api_key_id
            WHERE d.smc_domain_name = COALESCE(NULLIF(t.default_domain, ''), 'Shared Domain')
        """), {"now": datetime.now(timezone.utc)})
        access_created = result.rowcount if result.rowcount is not None else 0

        db.session.commit()
        log.warning("Phase A complete: %d Domains created, %d UserDomainAccess "
                    "rows migrated. Legacy tables (tenants, user_tenant_access) "
                    "kept intact until Phase B cutover.",
                    domains_created, access_created)
    except Exception as exc:
        db.session.rollback()
        log.error("Phase A FAILED — rolling back. Backup at %s. Error: %s",
                  backup_path, exc)
        raise


def _add_api_keys_columns(db):
    """ALTER TABLE api_keys to add the columns absorbed from Tenant.
    Each ALTER is wrapped in its own try/except so a partial-state DB
    (column already added in a previous failed run) doesn't block the
    rest of the additions.
    """
    additions = [
        ("smc_url",            "VARCHAR(512) NULL"),
        ("verify_ssl",         "BOOLEAN NOT NULL DEFAULT 0"),
        ("timeout",            "INTEGER NOT NULL DEFAULT 120"),
        ("api_version",        "VARCHAR(16) NULL"),
        ("flexedge_source_ip", "VARCHAR(45) NOT NULL DEFAULT ''"),
    ]
    cols = _sqlite_columns(db, "api_keys")
    for name, decl in additions:
        if name in cols:
            continue
        log.info("Phase A: ALTER api_keys ADD COLUMN %s", name)
        db.session.execute(db.text(f"ALTER TABLE api_keys ADD COLUMN {name} {decl}"))


def _sqlite_tables(db) -> list[str]:
    """List user tables in the SQLite DB."""
    try:
        rows = db.session.execute(db.text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )).all()
        return [row[0] for row in rows]
    except Exception:
        return []


# ── Multi-Domain Revamp — Phase B.1 ──────────────────────────────────────
#
# Adds `domain_id` to every feature table that today is keyed by
# (tenant_id, api_key_id). Backfills the new column by joining against the
# `domains` table created in Phase A.
#
# The legacy `tenant_id` and `api_key_id` columns are KEPT (Phase B.1 is
# additive and reversible). They'll be dropped in Phase B.3 once every
# query callsite has been switched to `domain_id`.
#
# Tables that get a NOT-NULL-after-backfill domain_id (operational data):
#   - tls_deployments
#   - dhcp_scopes
#   - dhcp_engine_credentials
#   - dhcp_engine_ssh_access
#   - optimization_submissions
#
# Tables that get a NULLABLE domain_id (audit logs — legacy rows stay NULL):
#   - tls_activity_logs
#   - dhcp_activity_logs

# (table_name, has_api_key_id) — identifies which tables had both
# (tenant_id, api_key_id) and which only had tenant_id.
_PHASE_B1_OPERATIONAL_TABLES = [
    ("tls_deployments",         True),
    ("dhcp_scopes",             True),
    ("dhcp_engine_credentials", True),
    ("dhcp_engine_ssh_access",  True),
    ("optimization_submissions", False),  # tenant_id only — derive domain via api_keys.tenant_id
]

_PHASE_B1_LOG_TABLES = [
    "tls_activity_logs",
    "dhcp_activity_logs",
]


def _phase_b1_feature_domain_ids(db, app):
    """Phase B.1: add domain_id to every feature table + backfill it.

    Idempotent. The presence of `domain_id` on `dhcp_scopes` is the cheap
    signal that B.1 already ran (we add it to all tables in the same run,
    so any one of them is a fine sentinel).
    """
    if not _is_sqlite(app):
        return  # Real DBA territory.

    cols = _sqlite_columns(db, "dhcp_scopes")
    if not cols:
        return  # Table doesn't exist yet (very fresh install before db.create_all).

    if "domain_id" in cols:
        return  # Already applied.

    if "domains" not in _sqlite_tables(db):
        return  # Phase A hasn't run — defer.

    log.warning("Phase B.1: starting feature-table domain_id backfill")
    backup_path = _backup_sqlite_db(app, suffix="pre-phase-b1")
    if backup_path:
        log.warning("Phase B.1: backup at %s", backup_path)

    try:
        # Operational tables: ADD domain_id, then backfill.
        for table, has_api_key_id in _PHASE_B1_OPERATIONAL_TABLES:
            tcols = _sqlite_columns(db, table)
            if not tcols:
                log.info("Phase B.1: %s table absent — skipping", table)
                continue
            if "domain_id" in tcols:
                continue

            log.info("Phase B.1: ALTER %s ADD COLUMN domain_id", table)
            db.session.execute(db.text(
                f"ALTER TABLE {table} ADD COLUMN domain_id INTEGER NULL "
                f"REFERENCES domains(id) ON DELETE CASCADE"
            ))

            # Backfill. The lookup uses the tenant's default_domain (same
            # rule used during Phase A to create Domain rows), matching one
            # Domain per (api_key_id, smc_domain_name).
            if has_api_key_id:
                # Tables with both tenant_id + api_key_id: match by api_key_id
                # (preferred) and fall back to tenant_id+default_domain.
                sql = f"""
                    UPDATE {table}
                    SET domain_id = (
                        SELECT d.id
                        FROM domains d
                        JOIN tenants t ON t.id = (
                            SELECT tenant_id FROM api_keys WHERE id = {table}.api_key_id
                        )
                        WHERE d.api_key_id = {table}.api_key_id
                          AND d.smc_domain_name = COALESCE(NULLIF(t.default_domain, ''), 'Shared Domain')
                        LIMIT 1
                    )
                    WHERE domain_id IS NULL
                """
            else:
                # Tables with only tenant_id (e.g. optimization_submissions):
                # there's no api_key context, so pick ANY Domain belonging to
                # any ApiKey under that tenant. Tie-break: lowest domain id.
                sql = f"""
                    UPDATE {table}
                    SET domain_id = (
                        SELECT d.id
                        FROM domains d
                        JOIN api_keys ak ON ak.id = d.api_key_id
                        JOIN tenants t  ON t.id = ak.tenant_id
                        WHERE t.id = {table}.tenant_id
                          AND d.smc_domain_name = COALESCE(NULLIF(t.default_domain, ''), 'Shared Domain')
                        ORDER BY d.id ASC
                        LIMIT 1
                    )
                    WHERE domain_id IS NULL
                """
            db.session.execute(db.text(sql))

            # Sanity: how many rows still NULL? If any, we leave them but log loudly.
            unfilled = db.session.execute(db.text(
                f"SELECT COUNT(*) FROM {table} WHERE domain_id IS NULL"
            )).scalar() or 0
            total = db.session.execute(db.text(
                f"SELECT COUNT(*) FROM {table}"
            )).scalar() or 0
            log.info("Phase B.1: %s — %d/%d rows backfilled (%d still NULL)",
                     table, total - unfilled, total, unfilled)

        # Log tables: ADD domain_id (nullable, no backfill — legacy rows
        # predate per-domain logging and stay NULL).
        for table in _PHASE_B1_LOG_TABLES:
            tcols = _sqlite_columns(db, table)
            if not tcols:
                continue
            if "domain_id" in tcols:
                continue
            log.info("Phase B.1: ALTER %s ADD COLUMN domain_id (nullable, no backfill)", table)
            db.session.execute(db.text(
                f"ALTER TABLE {table} ADD COLUMN domain_id INTEGER NULL "
                f"REFERENCES domains(id) ON DELETE SET NULL"
            ))

        db.session.commit()
        log.warning("Phase B.1 complete: domain_id added to all feature tables. "
                    "Legacy tenant_id/api_key_id columns kept until Phase B.3.")
    except Exception as exc:
        db.session.rollback()
        log.error("Phase B.1 FAILED — rolling back. Backup at %s. Error: %s",
                  backup_path, exc)
        raise


# ── Platform-log unification (one-shot backfill) ─────────────────────────
#
# The standing rule (memory: feedback_logging_standing_rule) directs every
# feature to funnel its audit + operational entries through one platform
# log table. The legacy per-feature tables (dhcp_activity_logs,
# tls_activity_logs) keep the historical rows accessible, but every NEW
# write goes to platform_logs (see shared/logging.py).
#
# This migration runs ONCE on first boot after the platform_logs table
# exists. It:
#   1. Copies dhcp_activity_logs rows → platform_logs as feature='dhcp'
#   2. Copies tls_activity_logs rows → platform_logs as feature='tls'
#   3. Seeds default platform_settings rows (log_mode, retention_days)
#   4. Marks the migration done via platform_settings.legacy_logs_migrated
#
# After this lands, the legacy tables stay around (read-only) but no new
# rows are ever inserted into them — every new entry goes via
# shared.logging.audit() / op() into platform_logs.

def _phase_log_unification(db, app):
    """Backfill platform_logs from the legacy activity tables. Idempotent."""
    if not _is_sqlite(app):
        return  # Real DBA territory.

    plog_cols = _sqlite_columns(db, "platform_logs")
    if not plog_cols:
        return  # Table doesn't exist yet (db.create_all hasn't built it).

    # Sentinel: legacy_logs_migrated=1 in platform_settings means we ran.
    try:
        marker = db.session.execute(db.text(
            "SELECT value FROM platform_settings WHERE key = 'legacy_logs_migrated'"
        )).first()
    except Exception:
        marker = None
    if marker and (marker[0] or "") == "1":
        return  # Already ran on a previous boot.

    log.info("Platform log unification: backfilling from legacy tables")

    try:
        # Seed defaults — only insert if missing.
        defaults = {
            "log_mode": "normal",
            "log_retention_days": "90",
        }
        for k, v in defaults.items():
            db.session.execute(db.text(
                "INSERT OR IGNORE INTO platform_settings (key, value, updated_at) "
                "VALUES (:k, :v, :now)"
            ), {"k": k, "v": v, "now": datetime.now(timezone.utc)})

        copied_dhcp = 0
        copied_tls = 0

        if "dhcp_activity_logs" in _sqlite_tables(db):
            # Map: category → feature ('engines' / 'dhcp'), with 'system'
            # category preserved as feature='system' so retention preserves
            # the gate signals (Phase 0 validation, log sweeps).
            #
            # We replay legacy DhcpActivityLog rows into platform_logs:
            #  - level = 'audit' (legacy audit-only table)
            #  - feature = 'system' if legacy.category='system' else 'dhcp'
            #  - action = legacy.category + '.' + legacy.action (e.g. "scope.create")
            #  - timestamp from legacy.created_at
            #  - domain_id passes through (was added by Phase B.1)
            result = db.session.execute(db.text("""
                INSERT INTO platform_logs (
                    timestamp, level, feature, action, status,
                    user_email, target, detail, domain_id, source_correlation_id
                )
                SELECT
                    created_at,
                    'audit',
                    CASE WHEN category = 'system' THEN 'system' ELSE 'dhcp' END,
                    category || '.' || action,
                    status,
                    NULL,
                    target,
                    detail,
                    domain_id,
                    NULL
                FROM dhcp_activity_logs
            """))
            copied_dhcp = result.rowcount or 0

        if "tls_activity_logs" in _sqlite_tables(db):
            result = db.session.execute(db.text("""
                INSERT INTO platform_logs (
                    timestamp, level, feature, action, status,
                    user_email, target, detail, domain_id, source_correlation_id
                )
                SELECT
                    created_at,
                    'audit',
                    CASE WHEN category = 'system' THEN 'system' ELSE 'tls' END,
                    category || '.' || action,
                    status,
                    NULL,
                    target,
                    detail,
                    domain_id,
                    NULL
                FROM tls_activity_logs
            """))
            copied_tls = result.rowcount or 0

        # Mark done.
        db.session.execute(db.text(
            "INSERT OR REPLACE INTO platform_settings (key, value, updated_at) "
            "VALUES ('legacy_logs_migrated', '1', :now)"
        ), {"now": datetime.now(timezone.utc)})

        db.session.commit()
        log.warning("Platform log unification: copied %d DHCP + %d TLS legacy rows "
                    "into platform_logs. Legacy tables kept read-only.",
                    copied_dhcp, copied_tls)
    except Exception as exc:
        db.session.rollback()
        log.error("Platform log unification FAILED: %s", exc)
        # Don't raise — boot must continue. The legacy tables are still readable.


# ── Change Management — Phase A (role columns + backfill) ────────────────
#
# Spec: docs/ChangeManagementProcess.md (Q10 — refined ROLES management).
#
# Four-tier role model (refined 2026-05-01 per operator clarification —
# Global Admin scope is per-Domain, not global):
#
#   SUPER ADMIN     users.is_super_admin = TRUE
#                   Singular bootstrap admin. Sees every Domain (no per-row
#                   UserDomainAccess required). Only role allowed cross-
#                   Domain infrastructure ops (Tenant / API Key / Domain
#                   CRUD). Set on the very first user by the setup wizard.
#
#   GLOBAL ADMIN    user_domain_access.role = 'global_admin'
#                   Per-Domain. Full power within assigned Domains —
#                   including Confirm/Revoke for `to_be_deleted` queue
#                   items and Domain Admin / Operator role management
#                   within that Domain. Multiple per Domain allowed.
#
#   DOMAIN ADMIN    user_domain_access.role = 'admin'
#                   Per-Domain. Full CRUD on Domain-scoped objects, can
#                   invite Operators. Cannot Confirm deletes.
#
#   DOMAIN OPERATOR user_domain_access.role = 'operator'
#                   Per-Domain. CRU only; deletes go through the queue.
#
# Schema columns:
#   users.is_super_admin    BOOLEAN DEFAULT FALSE
#   user_domain_access.role VARCHAR(16) DEFAULT 'admin'
#                           ('global_admin' | 'admin' | 'operator')
#
# Backfill rule (preserves today's behavior on first boot):
#   * The user with the LOWEST id who was a legacy admin becomes
#     SUPER ADMIN (the bootstrap user). They see every Domain, including
#     ones added later.
#   * Other legacy admins (multi-admin deployments) get
#     UserDomainAccess.role='global_admin' on every Domain they had access
#     to — preserving their cross-Domain power within those Domains while
#     no longer giving them visibility into Domains they aren't assigned.
#   * Every UserDomainAccess row that is NOT promoted to global_admin
#     stays at the default role='admin' — Domain Admins keep their CRUD
#     authority everywhere they had it.
#
# Migration handles BOTH new installs (fresh ADD COLUMN) and the case
# where Phase A landed yesterday with the old `is_global_admin` name
# (RENAME COLUMN + re-narrow). Idempotent.

def _phase_change_mgmt_a(db, app):
    """Phase A: add/rename role columns + backfill four-tier model."""
    if not _is_sqlite(app):
        return  # Real DBA territory.

    user_cols = _sqlite_columns(db, "users")
    uda_cols = _sqlite_columns(db, "user_domain_access")

    if not user_cols:
        return  # Fresh install before db.create_all even ran.

    has_super_col = "is_super_admin" in user_cols
    has_legacy_global_col = "is_global_admin" in user_cols
    has_uda_role = bool(uda_cols) and "role" in uda_cols

    needs_super_col = not has_super_col
    needs_uda_col = bool(uda_cols) and not has_uda_role

    if has_super_col and has_uda_role:
        return  # Phase A (revised) already applied on a previous boot.

    log.warning("Change Management Phase A: ensuring role columns + backfilling")

    try:
        # Step 1 — bring the users.is_super_admin column online.
        # Three paths:
        #   (a) Brand-new column, never-existed → ADD COLUMN.
        #   (b) Yesterday's Phase A added is_global_admin → RENAME COLUMN
        #       (re-purposing the same column avoids a useless DROP+ADD).
        #   (c) Both columns somehow exist (test rerun, manual SQL) →
        #       skip rename.
        if needs_super_col:
            if has_legacy_global_col:
                log.info("Phase CM-A: RENAME COLUMN users.is_global_admin "
                         "→ users.is_super_admin (re-purposing yesterday's "
                         "column to the narrower bootstrap-admin meaning)")
                db.session.execute(db.text(
                    "ALTER TABLE users RENAME COLUMN is_global_admin "
                    "TO is_super_admin"
                ))
            else:
                log.info("Phase CM-A: ALTER users ADD COLUMN is_super_admin")
                db.session.execute(db.text(
                    "ALTER TABLE users ADD COLUMN is_super_admin "
                    "BOOLEAN NOT NULL DEFAULT 0"
                ))
                # Backfill: anyone with legacy User.role='admin' is a
                # candidate for super-admin (we narrow to lowest id below).
                db.session.execute(db.text(
                    "UPDATE users SET is_super_admin = 1 WHERE role = 'admin'"
                ))

        # Step 2 — narrow super-admin status to the bootstrap user.
        # The MIN(id) admin keeps it; everyone else gets demoted.
        bootstrap_id = db.session.execute(db.text(
            "SELECT MIN(id) FROM users "
            "WHERE is_super_admin = 1 OR role = 'admin'"
        )).scalar()
        if bootstrap_id is not None:
            # Demote: anyone except the bootstrap user.
            demoted = db.session.execute(db.text(
                "UPDATE users SET is_super_admin = 0 "
                "WHERE id != :bid AND is_super_admin = 1"
            ), {"bid": bootstrap_id})
            n_demoted = demoted.rowcount or 0
            # Promote the bootstrap user (no-op if already 1).
            db.session.execute(db.text(
                "UPDATE users SET is_super_admin = 1 WHERE id = :bid"
            ), {"bid": bootstrap_id})
            if n_demoted:
                log.info("Phase CM-A: narrowed super-admin to bootstrap "
                         "user id=%s; demoted %d other previously-admin user(s)",
                         bootstrap_id, n_demoted)
            else:
                log.info("Phase CM-A: confirmed super-admin = bootstrap "
                         "user id=%s (no other admins to demote)",
                         bootstrap_id)

        # Step 3 — bring user_domain_access.role online (default 'admin').
        if needs_uda_col:
            log.info("Phase CM-A: ALTER user_domain_access ADD COLUMN role")
            db.session.execute(db.text(
                "ALTER TABLE user_domain_access ADD COLUMN role "
                "VARCHAR(16) NOT NULL DEFAULT 'admin'"
            ))
            # Defensively normalize empty/null values to 'admin'.
            db.session.execute(db.text(
                "UPDATE user_domain_access SET role = 'admin' "
                "WHERE role IS NULL OR role = ''"
            ))

        # Step 4 — promote demoted ex-admins to per-Domain global_admin so
        # they keep power inside the Domains they were already assigned to.
        # Identifies users who: had role='admin' (legacy), are NOT the
        # bootstrap user, and have UserDomainAccess rows. Those rows get
        # role='global_admin'. No-op if there's only the bootstrap user.
        if bootstrap_id is not None and uda_cols:
            promoted = db.session.execute(db.text("""
                UPDATE user_domain_access
                SET role = 'global_admin'
                WHERE user_id IN (
                    SELECT id FROM users
                    WHERE role = 'admin' AND id != :bid
                )
                AND role = 'admin'
            """), {"bid": bootstrap_id})
            n_promoted = promoted.rowcount or 0
            if n_promoted:
                log.info("Phase CM-A: promoted %d UserDomainAccess row(s) "
                         "to role='global_admin' (former multi-admins keep "
                         "per-Domain GA power)", n_promoted)

        db.session.commit()

        # Final summary
        n_super = db.session.execute(db.text(
            "SELECT COUNT(*) FROM users WHERE is_super_admin = 1"
        )).scalar() or 0
        n_uda_total = db.session.execute(db.text(
            "SELECT COUNT(*) FROM user_domain_access"
        )).scalar() or 0
        n_uda_ga = db.session.execute(db.text(
            "SELECT COUNT(*) FROM user_domain_access WHERE role = 'global_admin'"
        )).scalar() or 0
        log.warning("Change Management Phase A complete. "
                    "super_admin=%d, user_domain_access total=%d "
                    "(global_admin=%d). The smc_objects + pending_changes "
                    "tables are now available (empty); Phases B–H wire them in.",
                    n_super, n_uda_total, n_uda_ga)
    except Exception as exc:
        db.session.rollback()
        log.error("Change Management Phase A FAILED: %s", exc)
        # Don't raise — without the new columns the app keeps running on
        # legacy User.role; the rest of the platform isn't blocked.
