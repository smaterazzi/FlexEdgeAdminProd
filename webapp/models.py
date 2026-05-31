"""
FlexEdgeAdmin — SQLAlchemy models.

Tables (admin / control plane):
  tenants              SMC server connections (LEGACY — being absorbed into api_keys; dropped in Phase B)
  users                Authenticated users (from Azure AD)
  api_keys             Encrypted SMC API keys + server-level config (smc_url, verify_ssl, timeout, …)
  domains              Operator-facing scope unit — one row per (api_key, smc_domain_name)
  user_domain_access   Junction: which users can use which Domains
  user_tenant_access   LEGACY — kept until Phase B cutover; backfilled into user_domain_access at boot.

Tables (features):
  managed_certificates TLS Manager — certbot-tracked certificates
  tls_deployments      TLS Manager — cert → engine deployments
  tls_deployment_logs  Per-deployment audit log
  tls_activity_logs    App-wide TLS activity log

  dhcp_scopes              DHCP Manager — per-engine interfaces with internal DHCP active
  dhcp_reservations        DHCP Manager — MAC→IP reservations (source of truth is SMC Host)
  dhcp_deployments         DHCP Manager — per-node push history
  dhcp_activity_logs       DHCP Manager — app-wide activity log
  dhcp_engine_credentials  DHCP Manager — per-node SSH password (root), Fernet-encrypted
  dhcp_engine_ssh_access   DHCP Manager — managed SSH-allow rule per engine (created in SMC)

  optimization_submissions  Rule-optimizer findings submitted for admin review

Multi-Domain Revamp — Phase A status (2026-04-29):
  * ApiKey absorbs the smc_url / verify_ssl / timeout / api_version / flexedge_source_ip
    fields previously on Tenant (the Tenant entity is going away in Phase B).
  * Domain + UserDomainAccess are the new operator-facing entities.
  * Phase A backfills these from the legacy tables and lets old + new coexist.
  * Phase B (later) drops tenants, user_tenant_access, and tenant_id/api_key_id from
    every feature table — replaced by domain_id everywhere.
"""

from datetime import datetime, timezone

from sqlalchemy import TypeDecorator, Text
from shared.db import db
from shared.encryption import encrypt_value, decrypt_value, hash_value


# ── Custom column type: transparent Fernet encryption ────────────────────

class EncryptedString(TypeDecorator):
    """A column type that encrypts on write and decrypts on read."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return encrypt_value(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return decrypt_value(value)
        return value


# ── Helpers ──────────────────────────────────────────────────────────────

def _utcnow():
    return datetime.now(timezone.utc)


# ── Models ───────────────────────────────────────────────────────────────

class Tenant(db.Model):
    __tablename__ = "tenants"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    smc_url = db.Column(db.String(512), nullable=False)
    verify_ssl = db.Column(db.Boolean, default=False, nullable=False)
    timeout = db.Column(db.Integer, default=120, nullable=False)
    default_domain = db.Column(db.String(255), default="", nullable=False)
    api_version = db.Column(db.String(16), nullable=True)
    flexedge_source_ip = db.Column(db.String(45), default="", nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    # Relationships
    api_keys = db.relationship("ApiKey", back_populates="tenant", lazy="dynamic")

    def __repr__(self):
        return f"<Tenant {self.slug!r}>"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(255), default="", nullable=False)
    # `role` is the legacy global role marker ("admin" | "viewer"). Kept for
    # now so legacy `user_manager.is_admin()` callers keep resolving the
    # same answer; replaced functionally by `is_super_admin` + per-Domain
    # `UserDomainAccess.role`.
    role = db.Column(db.String(32), default="viewer", nullable=False)
    # Four-tier role model (Change Management Q10, refined 2026-05-01):
    #   SUPER ADMIN     — User.is_super_admin=True. The bootstrap admin
    #                     (or anyone they explicitly promote). Sees every
    #                     Domain (no UserDomainAccess row needed) and is
    #                     the only role allowed cross-Domain infrastructure
    #                     ops (Tenant / API Key / Domain CRUD). Singular by
    #                     default — the setup wizard sets this on the first
    #                     user; further Super Admins are deliberately rare.
    #   GLOBAL ADMIN    — UserDomainAccess.role='global_admin'. Per-Domain.
    #                     Confirm/Revoke `to_be_deleted` queue items, manage
    #                     Domain Admin / Operator role assignments within
    #                     that Domain. Visible only on Domains they're
    #                     explicitly assigned to.
    #   DOMAIN ADMIN    — UserDomainAccess.role='admin'. Per-Domain. Full
    #                     CRUD on Domain-scoped objects, invite operators.
    #   DOMAIN OPERATOR — UserDomainAccess.role='operator'. Per-Domain. CRU
    #                     only; deletes go through the queue tagged
    #                     `to_be_deleted` for Global/Super Admin to confirm.
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)
    # Per-user UI preference: drag-and-drop order for sidebar sections.
    # Stored as a comma-separated list of section IDs (see base.html
    # `data-section-id` attributes). NULL / empty = use default order.
    # Sections present in the DB but not in this list (e.g. a new
    # feature added after the user last saved) render in their default
    # position at the bottom — never hidden.
    sidebar_section_order = db.Column(db.Text, default="", nullable=False)

    # Relationships
    domain_accesses = db.relationship("UserDomainAccess", back_populates="user", lazy="joined")
    created_api_keys = db.relationship("ApiKey", back_populates="created_by", lazy="dynamic")

    def __repr__(self):
        return f"<User {self.email!r}>"


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    encrypted_key = db.Column(EncryptedString, nullable=False)
    key_hash = db.Column(db.String(64), nullable=False, index=True)

    # Server-level config — absorbed from Tenant during the Multi-Domain Revamp
    # Phase A (2026-04-29). Each ApiKey inherently knows the SMC server it talks
    # to. The Tenant table is being removed in Phase B once the cutover lands.
    smc_url = db.Column(db.String(512), nullable=True)              # NOT NULL after backfill
    verify_ssl = db.Column(db.Boolean, default=False, nullable=False)
    timeout = db.Column(db.Integer, default=120, nullable=False)
    api_version = db.Column(db.String(16), nullable=True)
    flexedge_source_ip = db.Column(db.String(45), default="", nullable=False)

    # LEGACY: tenant_id stays during Phase A so the old Tenant relationship
    # keeps working until the cutover. Dropped in Phase B.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    tenant = db.relationship("Tenant", back_populates="api_keys")  # LEGACY (kept until tenants table is dropped)
    created_by = db.relationship("User", back_populates="created_api_keys")
    domains = db.relationship("Domain", back_populates="api_key", lazy="dynamic", cascade="all, delete-orphan")

    def set_key(self, plaintext: str):
        """Set the API key plaintext. Encrypts and hashes automatically."""
        self.encrypted_key = plaintext  # EncryptedString handles encryption
        self.key_hash = hash_value(plaintext)

    @property
    def decrypted_key(self) -> str:
        """Read the decrypted API key."""
        return self.encrypted_key  # EncryptedString handles decryption

    def __repr__(self):
        return f"<ApiKey {self.name!r} smc_url={self.smc_url!r}>"


# Multi-Domain Revamp Phase B.3 step 2: UserTenantAccess removed.
# The legacy table was dropped after every callsite migrated to
# UserDomainAccess (committed cf5c46b).


# ── Multi-Domain Revamp: new operator-facing entities ──────────────────────

class Domain(db.Model):
    """Operator-facing scope unit. One Domain = one (server, smc-domain, key)
    triple. Replaces the old "Profile" concept.

    Carries `slug` for CLI back-compat: `cli/connect.py --tenant <slug>`
    keeps working — the slug now resolves a Domain instead of a Tenant.
    During the Phase A migration each existing Tenant.slug is preserved on
    its derived Domain so existing operator scripts don't break.
    """
    __tablename__ = "domains"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    smc_domain_name = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("api_key_id", "smc_domain_name", name="uq_api_key_smc_domain"),
    )

    # Relationships
    api_key = db.relationship("ApiKey", back_populates="domains")
    user_accesses = db.relationship(
        "UserDomainAccess", back_populates="domain", lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<Domain {self.slug!r} smc={self.smc_domain_name!r}>"


class UserDomainAccess(db.Model):
    """Replaces UserTenantAccess. Each row grants a User access to one Domain.
    The `is_default` flag picks the auto-selected Domain on login (only one
    default per user enforced application-side).

    `role` is the per-Domain role (Change Management Q10, refined 2026-05-01):
      * `global_admin` — full power within this Domain INCLUDING the
                         Confirm/Revoke buttons for `to_be_deleted` queue
                         items. Can promote/demote Domain Admin and Operator
                         within the same Domain. Limited to the assigned
                         Domain — for cross-Domain visibility, see
                         `User.is_super_admin`.
      * `admin`        — Domain Admin: full CRUD on Domain-scoped objects,
                         can invite Operators (per Q13). Cannot Confirm
                         deletes; that's Global Admin / Super Admin only.
      * `operator`     — Domain Operator: CRU only; deletes go to the
                         queue tagged `to_be_deleted` awaiting a Global /
                         Super Admin confirm/revoke.
    Default is `admin` so existing assignments preserve today's behavior.
    """
    __tablename__ = "user_domain_access"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    role = db.Column(db.String(16), default="admin", nullable=False)
    # role values: 'global_admin' | 'admin' | 'operator'
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "domain_id", name="uq_user_domain"),
    )

    # Relationships
    user = db.relationship("User", back_populates="domain_accesses")
    domain = db.relationship("Domain", back_populates="user_accesses")

    def __repr__(self):
        return f"<UserDomainAccess user={self.user_id} domain={self.domain_id}>"


class ManagedCertificate(db.Model):
    """A certbot-managed certificate tracked for TLS deployment automation.

    Roadmap item 5 / Phase LE.1+LE.2 (2026-05-11): extended with the
    FEA-driven request lifecycle. The legacy rows (operator manually
    pointed `domain` + `certbot_lineage` at existing certbot output)
    keep working; new rows are created via `/tls/letsencrypt/new` and
    track their full lifecycle in this same table.

    Lifecycle: `pending` (queued) → `active` (certbot succeeded, cert
    on disk) | `failed` (last_error populated; operator retries) |
    `revoked` (cert revoked at LE).
    """
    __tablename__ = "managed_certificates"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(512), unique=True, nullable=False, index=True)
    certbot_lineage = db.Column(db.String(1024), nullable=False)
    last_cert_hash = db.Column(db.String(64), default="", nullable=False)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    # LE additions — nullable so legacy rows survive the migration unchanged.
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="SET NULL"),
                          nullable=True, index=True)
    requested_by_user_id = db.Column(db.Integer,
                                     db.ForeignKey("users.id", ondelete="SET NULL"),
                                     nullable=True)
    status = db.Column(db.String(16), default="active", nullable=False)
    last_error = db.Column(db.Text, default="", nullable=False)
    is_staging = db.Column(db.Boolean, default=False, nullable=False)
    pending_change_id = db.Column(
        db.Integer, db.ForeignKey("pending_changes.id", ondelete="SET NULL"),
        nullable=True,
    )
    next_renewal_after = db.Column(db.DateTime, nullable=True, index=True)
    account_id = db.Column(db.Integer,
                           db.ForeignKey("acme_accounts.id", ondelete="SET NULL"),
                           nullable=True)
    # Phase LE.4 (manual DNS-01) preallocates these so the schema doesn't
    # need a second migration when wildcards ship. Unused by LE.2.
    challenge_type = db.Column(db.String(16), default="http01", nullable=False)
    dns_challenge_state = db.Column(db.String(16), nullable=True)
    dns_challenge_record_name = db.Column(db.String(512), nullable=True)
    dns_challenge_record_value = db.Column(db.String(512), nullable=True)

    deployments = db.relationship("TLSDeployment", back_populates="certificate",
                                  lazy="dynamic", cascade="all, delete-orphan")
    fea_domain = db.relationship("Domain")
    requested_by = db.relationship("User", foreign_keys=[requested_by_user_id])
    pending_change = db.relationship("PendingChange",
                                     foreign_keys=[pending_change_id])
    account = db.relationship("AcmeAccount")

    def __repr__(self):
        return f"<ManagedCertificate {self.domain!r} status={self.status}>"


# ── Let's Encrypt CRUD (Roadmap item 5 / Phase LE, 2026-05-11) ───────────

class AcmeAccount(db.Model):
    """The deployment's single Let's Encrypt account.

    Q3 locked: one account per deployment. The account key itself lives
    at `<CERTBOT_CONFIG_DIR>/accounts/...` (Q4) — defaults to
    `/config/letsencrypt/accounts/`, which IS the writable volume
    inside the container (the literal `/etc/letsencrypt/` is read-only
    in the Docker image, so we redirect certbot's config-dir; see
    `webapp/letsencrypt_certbot.py`). This row only tracks the
    metadata FEA needs to render the account-management UI and the
    one-shot setup wizard. `is_staging=True` means this row points at
    LE's staging environment (acme-staging-v02.api.letsencrypt.org)
    instead of production; the next-issuance default depends on this
    flag plus the per-cert Q7 toggle.
    """
    __tablename__ = "acme_accounts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(256), nullable=False)
    account_url = db.Column(db.String(512), default="", nullable=False)
    tos_accepted_at = db.Column(db.DateTime, nullable=False)
    tos_accepted_by_email = db.Column(db.String(256), nullable=False)
    is_staging = db.Column(db.Boolean, default=True, nullable=False)
    key_file_path = db.Column(db.String(1024), default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow,
                           nullable=False)

    def __repr__(self):
        return (f"<AcmeAccount {self.email!r} "
                f"{'staging' if self.is_staging else 'production'}>")


class DomainCertPattern(db.Model):
    """Per-FEA-Domain glob allowlist for Let's Encrypt cert requests.

    Q6 + Q6a + Q6b locked: Domain Admin (self-service) configures
    which subject names their Domain can request certs for, using
    glob patterns like `*.prod.example.com`. The cert_request queue
    handler matches the requested FQDN against this Domain's allowed
    patterns before invoking certbot — Domains with no patterns can
    request nothing, which is the safe default.

    Pattern matching is implemented by `webapp/letsencrypt_allowlist.py`
    and uses `fnmatch.fnmatchcase` so the operator's mental model is
    standard shell globbing.
    """
    __tablename__ = "domain_cert_patterns"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    pattern = db.Column(db.String(512), nullable=False)
    created_by_user_id = db.Column(db.Integer,
                                   db.ForeignKey("users.id", ondelete="SET NULL"),
                                   nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    domain = db.relationship("Domain")
    created_by = db.relationship("User", foreign_keys=[created_by_user_id])

    __table_args__ = (
        db.UniqueConstraint("domain_id", "pattern",
                            name="uq_domain_cert_pattern"),
    )

    def __repr__(self):
        return (f"<DomainCertPattern domain={self.domain_id} "
                f"pattern={self.pattern!r}>")


class TLSDeployment(db.Model):
    """Deployment of a managed certificate to a specific Forcepoint engine."""
    __tablename__ = "tls_deployments"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("managed_certificates.id", ondelete="CASCADE"), nullable=False)
    # Phase B: domain_id is the canonical scope FK. tenant_id + api_key_id
    # remain populated by the migration backfill so existing code keeps
    # reading them until callsites are switched, but new writes only need
    # domain_id (the migration fills the legacy columns from domain.api_key
    # via a trigger-equivalent in app code).
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=True)

    engine_name = db.Column(db.String(256), nullable=False)
    service_name = db.Column(db.String(256), nullable=False)
    public_ipv4 = db.Column(db.String(45), nullable=False)
    private_ipv4 = db.Column(db.String(45), nullable=False)

    # SMC object names (set by the deployer)
    tls_credential_name = db.Column(db.String(256), default="", nullable=False)
    host_public_name = db.Column(db.String(256), default="", nullable=False)
    host_private_name = db.Column(db.String(256), default="", nullable=False)
    policy_rule_name = db.Column(db.String(256), default="", nullable=False)
    policy_section_name = db.Column(db.String(256), default="", nullable=False)

    auto_renew = db.Column(db.Boolean, default=True, nullable=False)
    last_deployed_at = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.String(32), default="pending", nullable=False)  # pending|deployed|failed
    last_error = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    certificate = db.relationship("ManagedCertificate", back_populates="deployments")
    domain = db.relationship("Domain")
    tenant = db.relationship("Tenant")           # LEGACY
    api_key = db.relationship("ApiKey", foreign_keys=[api_key_id])  # LEGACY (use domain.api_key instead)
    logs = db.relationship("TLSDeploymentLog", back_populates="deployment",
                           lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<TLSDeployment {self.service_name!r} → {self.engine_name!r}>"


class TLSDeploymentLog(db.Model):
    """Audit log for TLS deployment actions."""
    __tablename__ = "tls_deployment_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    deployment_id = db.Column(db.Integer, db.ForeignKey("tls_deployments.id", ondelete="CASCADE"), nullable=False)
    action = db.Column(db.String(64), nullable=False)   # deploy|renew|remove
    status = db.Column(db.String(32), nullable=False)   # success|failed
    details = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    deployment = db.relationship("TLSDeployment", back_populates="logs")


class SmtpConfig(db.Model):
    """Per-Domain SMTP configuration for cert-expiration alerts.

    Operator-facing TLS feature add 2026-05-31. One row per Domain;
    Domain Admin manages from ``/tls/smtp``. The password is stored
    Fernet-encrypted via the project-wide ``EncryptedString``
    transparent column so it's only ever decrypted at send-time
    inside the worker thread.

    Recipients + thresholds are CSV strings — simple to edit in a
    form textarea, no extra join table. Thresholds are positive
    integers in DAYS (default 30/14/7/3/1) — the expirations sweep
    fires one notification per (cert, threshold) pair.
    """
    __tablename__ = "smtp_configs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, unique=True, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, default=587, nullable=False)
    # security mode: "starttls" (default, port 587) | "ssl" (SMTPS, port 465) | "plain"
    security = db.Column(db.String(16), default="starttls", nullable=False)
    username = db.Column(db.String(255), default="", nullable=False)
    encrypted_password = db.Column(EncryptedString, default="", nullable=False)
    from_address = db.Column(db.String(255), nullable=False)
    from_name = db.Column(db.String(255), default="FlexEdgeAdmin", nullable=False)
    # Comma-separated recipient list. Validation happens at form-handling time.
    recipients_csv = db.Column(db.String(2048), default="", nullable=False)
    # Comma-separated integer thresholds in days. Default "30,14,7,3,1".
    thresholds_csv = db.Column(db.String(128), default="30,14,7,3,1", nullable=False)
    # Smoke-test bookkeeping — last result of the operator-clicked Test
    # button. Surfaces on the SMTP page so the operator knows the config
    # is reachable before relying on the lazy sweep.
    last_test_at = db.Column(db.DateTime, nullable=True)
    last_test_status = db.Column(db.String(16), default="", nullable=False)  # ok|failed|""
    last_test_error = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    domain = db.relationship("Domain")

    def __repr__(self):
        return f"<SmtpConfig domain_id={self.domain_id} host={self.host!r}>"


class CertExpirationNotification(db.Model):
    """Per-(cert, threshold) notification de-duplication ledger.

    Operator-facing TLS feature add 2026-05-31. The expirations sweep
    fires one alert per ManagedCertificate per crossed threshold, then
    records a row here so the next sweep doesn't re-fire the same
    alert. Rows survive across the cert's lifecycle — a renewed cert
    whose ``valid_to`` jumps back above the highest threshold doesn't
    invalidate prior rows; instead the sweep notices it's no longer
    near any threshold and exits.

    Threshold "fired" semantics: a row exists if and only if an alert
    has been sent (status=ok) OR attempted-and-failed (status=failed)
    for that exact (cert_id, threshold_days). The sweep retries
    failed rows by upserting status back to ok on next success.
    """
    __tablename__ = "cert_expiration_notifications"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    certificate_id = db.Column(
        db.Integer,
        db.ForeignKey("managed_certificates.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    threshold_days = db.Column(db.Integer, nullable=False)
    sent_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    status = db.Column(db.String(16), default="ok", nullable=False)  # ok|failed
    error = db.Column(db.Text, default="", nullable=False)
    # Snapshot of who got pinged + the days-to-expiry at send time so the
    # historical view is honest even if the SMTP config / cert lineage
    # later change.
    recipients_csv = db.Column(db.String(2048), default="", nullable=False)
    days_to_expiry = db.Column(db.Integer, nullable=False)

    certificate = db.relationship("ManagedCertificate")

    __table_args__ = (
        db.UniqueConstraint("certificate_id", "threshold_days",
                            name="uq_cert_threshold"),
    )

    def __repr__(self):
        return (f"<CertExpirationNotification cert_id={self.certificate_id} "
                f"threshold={self.threshold_days}d status={self.status}>")


class TLSActivityLog(db.Model):
    """Application-wide activity log for TLS operations."""
    __tablename__ = "tls_activity_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Phase B: optional domain_id so the unified Logs view can filter per-domain.
    # NULL on legacy rows (predate Phase B); set on every new entry.
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="SET NULL"), nullable=True)
    category = db.Column(db.String(32), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False)
    target = db.Column(db.String(256), default="", nullable=False)
    detail = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)

    domain = db.relationship("Domain")


# ── DHCP Manager models ─────────────────────────────────────────────────

class DhcpScope(db.Model):
    """A DHCP subnet managed on a specific engine interface.

    Discovered from SMC (one row per engine interface that has the internal
    DHCP server enabled). An operator opts a scope into FlexEdge management
    via `enabled_in_flexedge` before reservations can be deployed.
    """
    __tablename__ = "dhcp_scopes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Phase B: domain_id is canonical. tenant_id + api_key_id stay populated
    # by the migration backfill until callsites are switched.
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=True)

    engine_name = db.Column(db.String(256), nullable=False)
    interface_id = db.Column(db.String(32), nullable=False)      # "2" or "2.100" for VLAN
    interface_label = db.Column(db.String(256), default="", nullable=False)

    subnet_cidr = db.Column(db.String(64), nullable=False)       # "192.168.10.0/24"
    gateway = db.Column(db.String(45), default="", nullable=False)
    dhcp_pool_start = db.Column(db.String(45), default="", nullable=False)
    dhcp_pool_end = db.Column(db.String(45), default="", nullable=False)

    label = db.Column(db.String(256), default="", nullable=False)   # operator-settable display name
    enabled_in_flexedge = db.Column(db.Boolean, default=False, nullable=False)

    last_synced_from_smc_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        # LEGACY uniqueness — kept until Phase B3 drops tenant_id.
        db.UniqueConstraint("tenant_id", "engine_name", "interface_id", name="uq_dhcp_scope_engine_if"),
        # NEW canonical uniqueness — same logical constraint expressed via domain_id.
        db.UniqueConstraint("domain_id", "engine_name", "interface_id", name="uq_dhcp_scope_domain_if"),
    )

    domain = db.relationship("Domain")
    tenant = db.relationship("Tenant")           # LEGACY
    api_key = db.relationship("ApiKey", foreign_keys=[api_key_id])  # LEGACY (use domain.api_key)
    reservations = db.relationship("DhcpReservation", back_populates="scope",
                                   lazy="dynamic", cascade="all, delete-orphan")
    deployments = db.relationship("DhcpDeployment", back_populates="scope",
                                  lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DhcpScope {self.engine_name!r}/{self.interface_id} {self.subnet_cidr}>"


class DhcpReservation(db.Model):
    """A single MAC→IP reservation within a scope.

    Authoritative data lives on the SMC Host element: ``Host.name``,
    ``Host.address``, and the MAC stored inside ``Host.comment`` via a
    ``[flexedge:mac=aa:bb:cc:dd:ee:ff]`` marker. This row indexes the Host
    and caches the MAC/IP for fast sync-diff during deployment.
    """
    __tablename__ = "dhcp_reservations"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scope_id = db.Column(db.Integer, db.ForeignKey("dhcp_scopes.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    smc_host_name = db.Column(db.String(256), nullable=False)
    smc_host_href = db.Column(db.String(512), default="", nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    mac_address = db.Column(db.String(17), nullable=False)       # aa:bb:cc:dd:ee:ff

    status = db.Column(db.String(32), default="pending", nullable=False)
    # status ∈ pending|synced|out_of_sync|error|queued|push_failed
    #   queued       Phase E.2 — operator submitted a create/update; the
    #                corresponding PendingChange is in QUEUED state. The
    #                SMC Host doesn't exist yet (smc_host_href is empty).
    #   push_failed  Phase E.2 — push attempted, SMC rejected. last_error
    #                holds the formatted SMC error; the row offers a
    #                Retry button on the scope listing.
    last_synced_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, default="", nullable=False)
    # Origin of this row — empty for manually-added, "migration:<project_id>"
    # for FortiGate-import-generated rows. Used for the "From migration"
    # badge in the DHCP Manager UI and for traceability.
    source = db.Column(db.String(64), default="", nullable=False)
    # Phase E.2 — link to the PendingChange row that controls this
    # reservation when status ∈ ('queued', 'push_failed'). Cleared on
    # successful push. NULL otherwise.
    pending_change_id = db.Column(
        db.Integer,
        db.ForeignKey("pending_changes.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("scope_id", "mac_address", name="uq_dhcp_res_scope_mac"),
        db.UniqueConstraint("scope_id", "ip_address", name="uq_dhcp_res_scope_ip"),
    )

    scope = db.relationship("DhcpScope", back_populates="reservations")
    pending_change = db.relationship(
        "PendingChange", foreign_keys=[pending_change_id],
        post_update=True,
    )

    def __repr__(self):
        return f"<DhcpReservation {self.mac_address} → {self.ip_address} scope={self.scope_id}>"


class DhcpDeployment(db.Model):
    """One row per reservation-push attempt, per cluster node."""
    __tablename__ = "dhcp_deployments"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scope_id = db.Column(db.Integer, db.ForeignKey("dhcp_scopes.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    engine_name = db.Column(db.String(256), nullable=False)
    node_index = db.Column(db.Integer, nullable=False)
    node_hostname = db.Column(db.String(256), default="", nullable=False)

    action = db.Column(db.String(32), nullable=False)            # push|dry_run|verify|rollback|resync
    status = db.Column(db.String(16), nullable=False)            # ok|partial|failed
    reservations_count = db.Column(db.Integer, default=0, nullable=False)

    file_sha256_before = db.Column(db.String(64), default="", nullable=False)
    file_sha256_after = db.Column(db.String(64), default="", nullable=False)
    diff = db.Column(db.Text, default="", nullable=False)
    duration_ms = db.Column(db.Integer, default=0, nullable=False)
    error = db.Column(db.Text, default="", nullable=False)
    # Reload warning is a *secondary* signal — file write succeeded but the
    # dhcpd HUP didn't reach an active process. The deployment is still
    # considered ``status="ok"`` (operator can force a reload via SMC policy
    # refresh). Kept separate from ``error`` so the audit log doesn't
    # conflate "we wrote nothing" with "we wrote but didn't reload".
    reload_warning = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)

    scope = db.relationship("DhcpScope", back_populates="deployments")

    def __repr__(self):
        return f"<DhcpDeployment scope={self.scope_id} node={self.node_index} status={self.status}>"


class DhcpEngineCredential(db.Model):
    """Per-node SSH credential used to read/write DHCP config files on an
    NGFW engine node.

    Auth model: root + password (Fernet-encrypted). The password is set by
    FlexEdgeAdmin via SMC's `change_ssh_pwd` API at enrollment, so the
    operator never sees or types it. Host fingerprint is pinned on first
    contact (TOFU); subsequent connects fail closed if the engine's host
    keys change.

    Uniqueness: one credential per (tenant, engine, node_id). `node_id`
    comes from SMC so it survives engine renames or node reordering.
    """
    __tablename__ = "dhcp_engine_credentials"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Phase B: domain_id is canonical. tenant_id + api_key_id stay during
    # transition; backfilled by the migration.
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=True)

    engine_name = db.Column(db.String(256), nullable=False)
    node_index = db.Column(db.Integer, default=0, nullable=False)
    node_id = db.Column(db.String(128), default="", nullable=False)
    node_name = db.Column(db.String(256), default="", nullable=False)

    hostname = db.Column(db.String(256), nullable=False)       # routable IP or DNS
    ssh_port = db.Column(db.Integer, default=22, nullable=False)
    ssh_username = db.Column(db.String(64), default="root", nullable=False)

    encrypted_password = db.Column(EncryptedString, nullable=False)
    host_fingerprint = db.Column(db.String(128), default="", nullable=False)

    # P1 — contact-address-aware connect IP (2026-05-12).
    # When NOT empty, SSH callers dial this address instead of `hostname`
    # so a node-initiated cluster sitting behind 1:1 NAT can still be
    # reached via its public contact address. The SMC SSH allow rule's
    # destination Host element keeps using `hostname` (the engine's real
    # interface IP) because that's what the engine sees on inbound
    # packets; the override only affects which TCP socket FEA opens.
    # NULL / "" preserves today's behavior (dial hostname directly).
    connect_ip_override = db.Column(db.String(64), default="", nullable=False)

    last_verified_at = db.Column(db.DateTime, nullable=True)
    last_verify_status = db.Column(db.String(32), default="unverified", nullable=False)  # ok|failed|unverified
    last_error = db.Column(db.Text, default="", nullable=False)
    # Cache freshness — set whenever an op verifies this credential's state
    # (enroll, verify, force-reset, refresh, deploy with successful SSH).
    # Compared against now() to decide whether to surface a "stale, refresh
    # needed" warning. NULL on rows created before this column existed.
    state_refreshed_at = db.Column(db.DateTime, nullable=True, default=_utcnow)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "engine_name", "node_id", name="uq_dhcp_cred_engine_node"),    # LEGACY
        db.UniqueConstraint("domain_id", "engine_name", "node_id", name="uq_dhcp_cred_domain_node"),    # NEW
    )

    domain = db.relationship("Domain")
    tenant = db.relationship("Tenant")           # LEGACY
    api_key = db.relationship("ApiKey", foreign_keys=[api_key_id])  # LEGACY (use domain.api_key)

    def __repr__(self):
        return f"<DhcpEngineCredential {self.engine_name}/node{self.node_index}@{self.hostname}>"


class DhcpEngineSshAccess(db.Model):
    """Tracks the FlexEdge-managed SSH allow rule on an engine's policy.

    One row per engine (not per node — the rule covers the whole cluster).
    The rule's name acts as the tag we look it up by; if it disappears from
    the policy out of band, we surface a banner asking the operator to
    recreate it (per A2 spec).

    The rule is torn down when the operator clicks "Remove SSH rule" or
    when the *last* credential for the engine is deleted.
    """
    __tablename__ = "dhcp_engine_ssh_access"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Phase B: domain_id is canonical. tenant_id + api_key_id stay during
    # transition; backfilled by the migration.
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=True)

    engine_name = db.Column(db.String(256), nullable=False)
    policy_name = db.Column(db.String(256), default="", nullable=False)
    rule_name = db.Column(db.String(256), nullable=False)        # the tag — stable id
    rule_href = db.Column(db.String(512), default="", nullable=False)  # cached
    fea_source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), default="", nullable=False)  # IP we put in the rule (informational)

    created_by_email = db.Column(db.String(255), default="", nullable=False)
    last_seen_in_policy_at = db.Column(db.DateTime, nullable=True)
    # Cache freshness — set when the rule is verified present in SMC policy
    # (install, refresh, deploy preflight). Drives the same stale/refresh UX
    # as DhcpEngineCredential.state_refreshed_at.
    state_refreshed_at = db.Column(db.DateTime, nullable=True, default=_utcnow)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "engine_name", name="uq_dhcp_ssh_access_engine"),    # LEGACY
        db.UniqueConstraint("domain_id", "engine_name", name="uq_dhcp_ssh_access_domain"),    # NEW
    )

    domain = db.relationship("Domain")
    tenant = db.relationship("Tenant")           # LEGACY
    api_key = db.relationship("ApiKey", foreign_keys=[api_key_id])  # LEGACY (use domain.api_key)

    def __repr__(self):
        return f"<DhcpEngineSshAccess {self.engine_name} rule={self.rule_name!r}>"


class DhcpActivityLog(db.Model):
    """App-wide activity log for all DHCP Manager operations."""
    __tablename__ = "dhcp_activity_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Phase B: optional domain_id for the unified Logs view filter.
    # NULL on legacy rows; set on every new entry.
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="SET NULL"), nullable=True)
    category = db.Column(db.String(32), nullable=False)          # scope|reservation|ssh|deploy|system
    action = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False)            # ok|failed|info
    target = db.Column(db.String(256), default="", nullable=False)
    detail = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)

    domain = db.relationship("Domain")


class EngineTerminalSession(db.Model):
    """
    Audit log for browser-based SSH terminal sessions to engine nodes.

    One row per open/close cycle. Connect/disconnect events only — never
    keystroke contents (sudo passwords typed in shell would otherwise land
    in the audit table).
    """
    __tablename__ = "engine_terminal_sessions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    credential_id = db.Column(db.Integer,
                              db.ForeignKey("dhcp_engine_credentials.id", ondelete="SET NULL"),
                              nullable=True)
    engine_name = db.Column(db.String(256), nullable=False)
    node_index = db.Column(db.Integer, nullable=False)
    opened_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    closed_at = db.Column(db.DateTime, nullable=True)
    source_ip = db.Column(db.String(45), default="", nullable=False)
    close_reason = db.Column(db.String(64), default="", nullable=False)  # disconnect|replaced|error|server_close

    user = db.relationship("User", foreign_keys=[user_id])

    def __repr__(self):
        return f"<EngineTerminalSession #{self.id} user={self.user_id} {self.engine_name}/{self.node_index}>"


class OptimizationSubmission(db.Model):
    """
    Rule-optimizer finding snapshot submitted by an operator for admin review.

    ``findings_json`` holds the serialized list of findings produced by
    ``rule_optimizer.analyze_rules()``. Once reviewed, each finding inside
    the JSON blob gains a ``decision`` ("approved"|"rejected") and an
    optional ``decision_note``.
    """
    __tablename__ = "optimization_submissions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # Phase B: domain_id is canonical. tenant_id stays during transition;
    # backfilled by the migration.
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    policy_name = db.Column(db.String(255), nullable=False)

    submitted_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    submitted_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)

    findings_json = db.Column(db.Text, nullable=False)
    finding_count = db.Column(db.Integer, default=0, nullable=False)

    status = db.Column(db.String(20), default="pending", nullable=False, index=True)  # pending|reviewed|closed
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    admin_notes = db.Column(db.Text, default="", nullable=False)

    domain = db.relationship("Domain")
    tenant = db.relationship("Tenant")           # LEGACY
    submitted_by = db.relationship("User", foreign_keys=[submitted_by_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])

    def __repr__(self):
        return f"<OptimizationSubmission #{self.id} policy={self.policy_name!r} status={self.status}>"


# ── Engine scan history (Phase 1 of docs/Engines-ScanHistory.md) ─────────
#
# One row per persisted scan. Hosts are stored 1:N. Schedules + comparison
# + time-graph are layered on top in later phases — these two tables are
# the foundation.

class EngineScanRecord(db.Model):
    __tablename__ = "engine_scan_records"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True)
    schedule_id = db.Column(db.Integer, nullable=True, index=True)  # FK reserved for Phase 4

    engine_name = db.Column(db.String(255), nullable=False, index=True)
    node_index = db.Column(db.Integer, nullable=False)
    source_iface_id = db.Column(db.String(64), default="", nullable=False)
    source_iface_vlan = db.Column(db.String(32), default="", nullable=False)
    source_iface_label = db.Column(db.String(128), default="", nullable=False)  # "1.42"
    source_subnet_cidr = db.Column(db.String(64), default="", nullable=False)
    target_label = db.Column(db.String(255), default="", nullable=False)
    target_mode = db.Column(db.String(32), default="subnet", nullable=False)  # subnet|single_ip|custom_range
    ports_csv = db.Column(db.Text, default="", nullable=False)

    total_targets = db.Column(db.Integer, default=0, nullable=False)
    duration_ms = db.Column(db.Integer, default=0, nullable=False)
    icmp_replies = db.Column(db.Integer, default=0, nullable=False)
    arp_replies = db.Column(db.Integer, default=0, nullable=False)
    hosts_with_open = db.Column(db.Integer, default=0, nullable=False)
    online_ips = db.Column(db.Integer, default=0, nullable=False)

    comment = db.Column(db.Text, default="", nullable=False)
    starred = db.Column(db.Boolean, default=False, nullable=False, index=True)
    source = db.Column(db.String(32), default="manual", nullable=False)  # manual|scheduled|api
    source_correlation = db.Column(db.String(64), default="", nullable=False)

    started_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    finished_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    domain = db.relationship("Domain")
    user = db.relationship("User", foreign_keys=[user_id])
    hosts = db.relationship("EngineScanHost", back_populates="scan",
                            cascade="all, delete-orphan", lazy="dynamic")

    __table_args__ = (
        db.Index("ix_engine_scan_records_scope",
                 "domain_id", "engine_name", "source_iface_label",
                 "started_at"),
    )

    def __repr__(self):
        return (f"<EngineScanRecord #{self.id} {self.engine_name}/"
                f"{self.source_iface_label} @ {self.started_at:%Y-%m-%d %H:%M}>")


class EngineScanHost(db.Model):
    __tablename__ = "engine_scan_hosts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("engine_scan_records.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    ip = db.Column(db.String(45), nullable=False)
    ip_int = db.Column(db.BigInteger, default=0, nullable=False)  # numeric sort key
    icmp_reply = db.Column(db.Boolean, default=False, nullable=False)
    arp_reply = db.Column(db.Boolean, default=False, nullable=False)
    mac = db.Column(db.String(32), default="", nullable=False)
    hostname = db.Column(db.String(255), default="", nullable=False)
    open_ports_csv = db.Column(db.Text, default="", nullable=False)
    closed_ports_csv = db.Column(db.Text, default="", nullable=False)

    scan = db.relationship("EngineScanRecord", back_populates="hosts")

    __table_args__ = (
        db.UniqueConstraint("scan_id", "ip", name="uq_engine_scan_hosts_scan_ip"),
        db.Index("ix_engine_scan_hosts_sort", "scan_id", "ip_int"),
    )

    def __repr__(self):
        return f"<EngineScanHost #{self.id} scan={self.scan_id} ip={self.ip}>"


class EngineSginfoCollection(db.Model):
    """One sginfo archive collected from a node via SMC.

    The actual gzipped tar lives on disk under `archive_path` (typically
    `/config/sginfo/<id>/sginfo.gz`). The DB row is the operator-facing
    handle: status, audit metadata, error text, and a JSON index of the
    archive's members so the viewer can render the file tree without
    re-scanning the tarball on every page load.
    """
    __tablename__ = "engine_sginfo_collections"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True)

    engine_name = db.Column(db.String(255), nullable=False, index=True)
    node_index = db.Column(db.Integer, nullable=False)
    node_name = db.Column(db.String(255), default="", nullable=False)

    include_core_files = db.Column(db.Boolean, default=False, nullable=False)
    include_slapcat_output = db.Column(db.Boolean, default=False, nullable=False)

    status = db.Column(db.String(16), default="running", nullable=False, index=True)
    error = db.Column(db.Text, default="", nullable=False)

    archive_path = db.Column(db.String(512), default="", nullable=False)
    archive_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    member_count = db.Column(db.Integer, default=0, nullable=False)
    member_index_json = db.Column(db.Text, default="", nullable=False)

    duration_ms = db.Column(db.Integer, default=0, nullable=False)
    started_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    domain = db.relationship("Domain")
    user = db.relationship("User", foreign_keys=[user_id])

    def __repr__(self):
        return (f"<EngineSginfoCollection #{self.id} {self.engine_name}/"
                f"node{self.node_index} status={self.status}>")


# ── Platform-wide log management (replaces per-feature activity tables) ──
#
# Standing rule (memory: feedback_logging_standing_rule, 2026-04-29): every
# feature must funnel its audit + operational entries through one platform
# log system, NOT hand-rolled per-feature tables.
#
# `platform_logs` is the unified target. Legacy tables (dhcp_activity_logs,
# tls_activity_logs) are backfilled into it once at boot, then made read-only
# for the existing per-feature reader views — but every NEW write goes here.
#
# `platform_settings` is a generic key/value table; the log management
# subsystem uses the keys: log_mode, log_retention_days,
# feature_log_<feature_name>.

class PlatformLog(db.Model):
    """One unified audit + operational log row for every feature.

    `level`:
      * `audit` — user-triggered ops (always persisted)
      * `op` — operational details (persisted only when log_mode = verbose)

    `feature` is the feature-registry name ("dhcp", "tls", "engines",
    "migration", "admin", "auth", "optimizer"). The Logs settings page
    drives a per-feature on/off toggle keyed by this name.

    `source_correlation_id` groups a batch of related entries — e.g. a
    migration import #42 emits dozens of entries that share the same id
    so the Logs page can collapse them into one expandable group.
    """
    __tablename__ = "platform_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    level = db.Column(db.String(16), default="audit", nullable=False, index=True)
    feature = db.Column(db.String(64), nullable=False, index=True)
    action = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(16), default="ok", nullable=False)
    user_email = db.Column(db.String(256), nullable=True)
    target = db.Column(db.String(512), default="", nullable=False)
    detail = db.Column(db.Text, default="", nullable=False)
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="SET NULL"),
                          nullable=True)
    source_correlation_id = db.Column(db.String(64), nullable=True, index=True)

    # M8 (audit fix-up, 2026-05-09): the /logs viewer ALWAYS filters by
    # domain + timestamp + ORDER BY timestamp DESC. The previous
    # individually-indexed columns forced SQLite to choose one index
    # (timestamp) and scan; with rows accumulating across all Domains
    # the planner kept picking the wrong one. A composite index on
    # (domain_id, timestamp) lets the planner satisfy both predicates
    # AND the ORDER BY in one scan. Drops the standalone domain_id
    # index — redundant once the composite covers it.
    __table_args__ = (
        db.Index("ix_platform_logs_domain_ts", "domain_id", "timestamp"),
    )

    domain = db.relationship("Domain")

    def __repr__(self):
        return (f"<PlatformLog #{self.id} {self.feature}:{self.action} "
                f"({self.status})>")


class PlatformSetting(db.Model):
    """Generic key/value config table used by the log management subsystem.

    Known keys:
      * `log_mode` — "normal" | "verbose"
      * `log_retention_days` — integer string, default "90"
      * `feature_log_<name>` — "on" | "off" (default ON when row absent)
      * `legacy_logs_migrated` — "1" once the boot-time backfill has run
    """
    __tablename__ = "platform_settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow,
                           onupdate=_utcnow, nullable=False)
    updated_by_email = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f"<PlatformSetting {self.key}={self.value!r}>"


# ── Phase E.2 — Bypass Queue (per-domain capability + per-user override) ─

class FeatureBypassSetting(db.Model):
    """Per-domain, per-user "bypass queue" toggle.

    Two row shapes coexist in this table:

      1. **Domain capability** (`user_id IS NULL`) — gate that *allows*
         Domain Admins of the domain to grant per-user bypass for the
         feature. Toggling this on/off does NOT change operator
         behavior on its own; it just enables the per-user UI.

      2. **Per-user override** (`user_id IS NOT NULL`) — actually
         changes behavior. When `enabled=True`, the route auto-pushes
         the queue row inline (regardless of the user's role tier)
         and deletes the row on success. Audit log entry stays.

    Lookup hierarchy in `shared/queue_settings.should_bypass_queue`:
      * Per-user row first (most specific wins).
      * Otherwise: queue is the default (operators wait, admins
        auto-push but keep the queue row visible).

    Authority (enforced in routes, not the schema):
      * Domain capability — Domain Admin in the domain, Global Admin,
        Super Admin can toggle.
      * Per-user override — same admins, but Domain Admin can only
        edit when domain capability is ON for that feature.

    Operators have no edit rights; they can only view their own
    bypass status (read-only "Bypass active" badge in the UI).
    """
    __tablename__ = "feature_bypass_settings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    # NULL → domain-capability row; otherwise per-user override.
    user_id = db.Column(db.Integer,
                        db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=True, index=True)
    feature = db.Column(db.String(64), nullable=False, index=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False)

    updated_at = db.Column(db.DateTime, default=_utcnow,
                           onupdate=_utcnow, nullable=False)
    updated_by_id = db.Column(db.Integer,
                              db.ForeignKey("users.id", ondelete="SET NULL"),
                              nullable=True)

    domain = db.relationship("Domain")
    user = db.relationship("User", foreign_keys=[user_id])
    updated_by = db.relationship("User", foreign_keys=[updated_by_id])

    # SQLite treats NULL as distinct in UNIQUE constraints, so this
    # composite catches duplicates only for per-user rows. The
    # capability-row uniqueness ((domain_id, NULL, feature) → at most
    # one) is enforced at the application layer in
    # `shared/queue_settings.set_capability`.
    __table_args__ = (
        db.UniqueConstraint("domain_id", "user_id", "feature",
                            name="uq_feature_bypass"),
    )

    def __repr__(self):
        scope = "capability" if self.user_id is None else f"user={self.user_id}"
        return (f"<FeatureBypassSetting domain={self.domain_id} "
                f"feature={self.feature!r} {scope} enabled={self.enabled}>")


# ── Change Management — Phase A schema ───────────────────────────────────
#
# Spec: docs/ChangeManagementProcess.md
#
# Two new tables introduce the two-phase commit model:
#
#   smc_objects     The "SMCRelated" registry. Every SMC element FlexEdgeAdmin
#                   has read or written gets a row here. Drives drift
#                   detection (Q6) and the queue's per-object sub-queue (the
#                   ASSUMPTIONS hierarchical model).
#
#   pending_changes The queue itself. Each row is one mutating intent that
#                   is QUEUED in the FEA DB but NOT yet sent to SMC. The
#                   push runner (Phase C) drains this table.
#
# Phase A landing strategy: tables are created empty + defensively, no code
# yet enqueues into them and no UI surfaces them. Behavior is unchanged.
# Phases B-H wire them up.

class SmcObject(db.Model):
    """The `SMCRelated` registry — every SMC element FEA has touched.

    `smc_href` is the SMC-side identity (URL path under the SMC API root).
    Unique within a Domain. `smc_type` is the SMC element kind: 'host',
    'engine', 'policy', 'rule', 'nat_rule', 'service', 'service_group',
    'network', 'address_range', 'fqdn', 'zone', 'group', 'tls_credential',
    'dhcp_scope_reservation', etc.

    `last_seen_hash` is a stable digest of the SMC payload at the time we
    last read it. Drift detection (Phase G) compares this against a fresh
    SMC fetch — a mismatch surfaces as a drift card on the queue page.

    `is_to_be_deleted` is set when a Domain Operator submits a delete
    (Q10): the row stays in SMC (and in our other feature tables) but is
    flagged across the UI awaiting a Global Admin confirm/revoke. The
    actual delete only happens once the corresponding `pending_changes`
    row reaches PUSHED state.

    `managed_by_flexedge` distinguishes objects WE created (true) from
    objects we only track (false). Drift on FEA-managed objects is more
    surprising than drift on read-only tracked ones; the UI flags
    accordingly.
    """
    __tablename__ = "smc_objects"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    smc_href = db.Column(db.String(1024), nullable=False)
    smc_type = db.Column(db.String(64), nullable=False, index=True)
    smc_name = db.Column(db.String(512), default="", nullable=False)

    last_seen_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_seen_hash = db.Column(db.String(64), default="", nullable=False)

    managed_by_flexedge = db.Column(db.Boolean, default=False, nullable=False)
    is_to_be_deleted = db.Column(db.Boolean, default=False, nullable=False)

    # Phase G — drift detector. Updated by `shared.smc_drift.scan_domain_drift`.
    #   drift_state ∈ {'unknown', 'clean', 'drifted', 'gone'}
    #   'unknown' = never scanned / hash not yet baselined
    #   'clean'   = hash matches last scan
    #   'drifted' = SMC element exists but its hash differs from last_seen_hash
    #   'gone'    = SMC element no longer exists (404 from SMC)
    # `drift_detail` carries a short human-readable summary ("address: 10.0.0.1
    # → 10.0.0.5") for the queue UI.
    drift_state = db.Column(db.String(16), default="unknown", nullable=False)
    last_drift_check_at = db.Column(db.DateTime, nullable=True)
    drift_detail = db.Column(db.String(512), default="", nullable=False)

    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow,
                           onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("domain_id", "smc_href", name="uq_smc_object_href"),
    )

    domain = db.relationship("Domain")
    pending_changes = db.relationship(
        "PendingChange", back_populates="smc_object",
        lazy="dynamic", cascade="all, delete-orphan",
    )

    def __repr__(self):
        return (f"<SmcObject #{self.id} {self.smc_type}:{self.smc_name!r} "
                f"href={self.smc_href!r}>")


class PendingChange(db.Model):
    """Two-phase commit queue row — one mutating intent staged for review.

    State machine (see ChangeManagementProcess.md § "Two-phase commit model"):

        QUEUED ──Push──► PUSHED ──(engine activation)──► APPLIED
           │               │
           │               └── (SMC error) ──► PUSH_FAILED
           │
           └── (operator clicks Abort) ──► ABORTED
           └── (loses a conflict resolution) ──► ABORTED

    Hierarchical queue (the ASSUMPTIONS block):
      * `created_at` — drives the MAIN-QUEUE time order (global view).
      * `smc_object_id` — groups rows into a per-object sub-queue. Within
        a sub-queue the order is FIFO by `created_at`.
      * `scheduled_after` — explicit dependency (e.g. a section CREATE
        must succeed before the rule CREATE that references it). The
        push runner respects this on top of (sub-queue, created_at).

    Migration import bulk (Q8):
      * `scope='migration_review'` rows live in a separate review queue;
        the operator validates them before promoting to `scope='main'`.

    Conflict resolution (Q2):
      * When a new change collides with an existing QUEUED change on the
        same object, both rows get `state='conflict'` and `conflict_with_id`
        cross-links them. The resolver (≥ Domain Admin) picks the winner;
        the loser transitions to ABORTED with `push_error_text` describing
        which row won.

    Operator-submitted delete (Q10):
      * `operation='to_be_deleted'` is the Domain Operator's request.
      * The Global Admin confirm step transitions the same row to
        `operation='delete'` + `state='queued'` (or directly to PUSHED
        if confirm-and-push is one click). The revoke step transitions
        it to ABORTED.
    """
    __tablename__ = "pending_changes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer,
                          db.ForeignKey("domains.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True, index=True)
    smc_object_id = db.Column(db.Integer,
                              db.ForeignKey("smc_objects.id", ondelete="SET NULL"),
                              nullable=True, index=True)

    # 'main' (production queue) | 'migration_review' (staging area for a
    # migration import batch — operator validates before promoting).
    scope = db.Column(db.String(32), default="main", nullable=False, index=True)

    # 'create' | 'update' | 'delete' | 'to_be_deleted' | 'create_section'
    # | 'upload_policy' | 'reload_dhcp'
    operation = db.Column(db.String(32), nullable=False, index=True)

    # JSON-encoded payload (full new state for create / diff for update /
    # the scope+ip+mac triple for reservation reload / etc.). Schema
    # depends on `operation`; documented per-operation in the push runner.
    payload_json = db.Column(db.Text, default="{}", nullable=False)

    feature_source = db.Column(db.String(32), nullable=False, index=True)
    source_correlation_id = db.Column(db.String(64), nullable=True, index=True)

    state = db.Column(db.String(32), default="queued", nullable=False, index=True)
    # 'queued' | 'pushed' | 'applied' | 'aborted' | 'push_failed' | 'conflict'

    scheduled_after = db.Column(db.Integer,
                                db.ForeignKey("pending_changes.id",
                                              ondelete="SET NULL"),
                                nullable=True)
    conflict_with_id = db.Column(db.Integer,
                                 db.ForeignKey("pending_changes.id",
                                               ondelete="SET NULL"),
                                 nullable=True, index=True)

    push_error_text = db.Column(db.Text, default="", nullable=False)
    push_error_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)
    transitioned_at = db.Column(db.DateTime, nullable=True)
    transitioned_by_id = db.Column(db.Integer,
                                   db.ForeignKey("users.id", ondelete="SET NULL"),
                                   nullable=True)

    domain = db.relationship("Domain")
    user = db.relationship("User", foreign_keys=[user_id])
    transitioned_by = db.relationship("User", foreign_keys=[transitioned_by_id])
    smc_object = db.relationship("SmcObject", back_populates="pending_changes")
    depends_on = db.relationship(
        "PendingChange", remote_side=[id], foreign_keys=[scheduled_after],
        post_update=True,
    )

    def __repr__(self):
        return (f"<PendingChange #{self.id} {self.operation} "
                f"scope={self.scope} state={self.state}>")


def enable_wal_mode(app):
    """Enable WAL mode for SQLite after db.init_app(). Call from app setup."""
    with app.app_context():
        if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
            with db.engine.connect() as conn:
                conn.execute(db.text("PRAGMA journal_mode=WAL"))
                conn.commit()
