# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.2.0-dev] - 2026-04-29 → 2026-05-31

### Engine SSH Credentials — per-engine FEA source-IP override (2026-05-31)

The SSH allow rule's **source** (the FEA address the engine sees on inbound TCP/22) was previously always the domain-wide `flexedge_source_ip` — one IP for every engine in the domain. Operators behind 1:1 NAT, where FEA reaches different engines from different egress addresses, had no way to set a per-engine source. Now the SSH-allow-rule block carries an editable **"FEA source IP for this rule"** field, pre-filled with the domain default but overridable per engine.

- `credentials_rule_install` reads the optional `fea_source_ip` form field, validates it via `ipaddress.ip_address()`, and uses it as the rule's source for that engine; falls back to the domain default (`tenant.flexedge_source_ip`) when blank. The persisted `DhcpEngineSshAccess.fea_source_ip` already records whatever source the rule was installed with, so the override naturally survives on the row — no schema change needed.
- The drift-resolution **Overwrite** / **Add** buttons (shown when an existing rule's live source doesn't match) now carry their own editable IP field too, so a cutover or transition can target a manually-typed address rather than only the domain default. Shared resolver `_resolve_override_source_ip(form, domain)` validates the `new_source_ip` field and falls back to the domain default.
- The empty-source guard was relaxed: a blank domain default no longer hard-blocks node discovery (`credentials_discover_nodes`). The operator can reach the rule step and type a per-engine IP there; the install path refuses only if BOTH the override field and the domain default are empty, with a message pointing at the field + the Source IP card.
- Mirrors the existing "custom destination IP" affordance (2026-05-13) on the source side. Complements the P1 NAT `connect_ip_override` (the IP FEA *dials*) — this is the IP the engine *sees*, i.e. the rule's source Host. The two are independent: behind 1:1 NAT, FEA dials the public contact address while the rule source is FEA's NAT egress as the engine observes it.

Verified end-to-end with the Flask test client: invalid override → HTTP 400 before any SMC call; no-override-and-no-domain-default → HTTP 400 with the new guard message; valid override threads into `enqueue_install_ssh_rule(source_ip=…)` unchanged; the editable `fea_source_ip` + `new_source_ip` fields render on `/dhcp/credentials`. Module: [webapp/dhcp_manager.py](webapp/dhcp_manager.py) (`credentials_rule_install`, `credentials_rule_source_overwrite`, `credentials_rule_source_add`, `_resolve_override_source_ip`, relaxed `credentials_discover_nodes`); template: [webapp/templates/dhcp/credentials.html](webapp/templates/dhcp/credentials.html).

### Sidebar — drag-and-drop section reorder, per-user (2026-05-31)

Every sidebar section (Navigation, Network Objects, Services, Infrastructure, Migration, Optimizer, Change Queue, TLS Manager, Engines, DHCP Manager, Logs, Administration) is now HTML5-draggable. Operators reorder by grabbing a section's header (a `bi-grip-vertical` icon hints the affordance) and dropping above or below another section; the new order is persisted server-side on `User.sidebar_section_order` (per-user — different operators get different layouts on the same browser, layouts sync across browsers).

**Server-side rendering of the saved order** — no FOUC. The base template builds a default order (gated by role: Operator-only sections appear for `is_domain_operator`, Administration for `is_domain_admin`), reads `user_sidebar_order` from the inject_globals helper, then emits sections in the saved order first followed by any unsaved sections in their default position. A section added in a future release never gets hidden — it renders at the bottom of its default group until the operator re-drops to position it.

**Whitelisted persistence** at `POST /api/sidebar-order`. The endpoint accepts `{"order": [...]}` and filters every entry against a frozenset of the 12 known section IDs. Junk values (path traversal attempts, made-up keys) are silently dropped; duplicate / mixed-case IDs are deduped to lowercase-first-seen; non-list payloads return HTTP 400; unauthenticated POSTs hit the `@login_required` gate and 302 to login. The persisted column length is hard-capped at the size of the whitelist so repeated POSTs can't grow the row unboundedly.

**Drag-drop UX details.** Native HTML5 drag-and-drop — zero new JS deps (matches the standing rule of vendoring functional assets locally). Each `.sidebar-section` carries the `draggable="true"` attribute; the drag is suppressed when the operator's `mousedown` originates on a `<a>` / `<button>` / `.nav-link` so links remain clickable. Visual cues: faded `.dragging` ghost on the source; thin top/bottom indigo edge on the section the cursor is over (top half = drop above, bottom half = drop below). Drop fires the DOM move + the persistence POST via the existing `window.fexFetch` wrapper (auto-attaches `X-CSRFToken`).

**Schema migration.** Additive column `users.sidebar_section_order TEXT NOT NULL DEFAULT ""` added via the existing `_migrate_post_create` flow — picks up on next boot without operator intervention. Legacy User rows get the default empty value, which means "use the rendered order from base.html" — exactly today's behavior.

Modules: column on `User` in [webapp/models.py](webapp/models.py); migration in [webapp/db_init.py](webapp/db_init.py) `_migrate_post_create`; API endpoint `api_sidebar_order_save` + `_ALLOWED_SIDEBAR_SECTIONS` whitelist in [webapp/app.py](webapp/app.py); injection variable `user_sidebar_order` in the same file's `inject_globals`; template macros + ordered render loop + CSS + drag IIFE in [webapp/templates/base.html](webapp/templates/base.html).

### TLS Manager — expiration dashboard + SMTP alerts (2026-05-31)

Operator-requested counterpart to the PFX import. Closes the loop on cert lifecycle: import / track / deploy / **get pinged 30 / 14 / 7 / 3 / 1 days before expiry** / renew. Works uniformly across all three cert sources (LE HTTP-01, LE DNS-01 wildcards, PFX-imported) — they're all `ManagedCertificate` rows with an on-disk `cert.pem` whose `not_valid_after` the new module reads at sweep time.

**Per-Domain SMTP configuration** at `/tls/smtp`. New `SmtpConfig` model (one row per Domain) carries `host`, `port`, `security ∈ {starttls, ssl, plain}`, `username`, Fernet-encrypted `password` via the project-wide `EncryptedString` column type, `from_address` + `from_name`, comma-separated `recipients_csv`, comma-separated `thresholds_csv` (default `30,14,7,3,1`), and an `is_active` toggle for pausing alerts without losing the config. Form validates at submit time: rejects bad port, empty recipients, recipients without `@`, empty thresholds. Editing keeps an existing password when the form field is left blank (`keep_password=1` hidden input + matching server-side guard) so operators don't have to retype on every edit.

**Lazy-sweep scheduler** in `webapp/cert_expirations.py` follows the LE.3 pattern: every visit to `/tls/expirations` calls `ensure_lazy_expiration_sweep()`, guarded by `platform_settings.tls_expirations_last_sweep_at` (default interval 1h). Cross-Domain by design — one sweep walks every active Domain that has a usable SmtpConfig + at least one recipient. For each cert it reads `<lineage>/cert.pem` to get the *live* `not_valid_after` (the DB doesn't cache this — a renewed lineage's new expiry shows up on the next sweep without any explicit invalidation step), computes `days_to_expiry`, then picks the smallest threshold `T` such that `dte ≤ T` AND `T` hasn't fired yet for that cert.

**Idempotency correctness** is the load-bearing property. The first attempt at the picking logic had a subtle bug — when the smallest qualifying threshold was already fired, the loop scanned upward to the next-higher threshold and fired *that* instead, producing a duplicate alert at T=14 the day after T=7 fired. Fix: once the smallest qualifying T is identified, either fire it OR exit; never scan upward. Verified via three back-to-back sweeps in the verification harness — eml file count goes 0→1→1→1 and notification row count stays at 1. A cert with 200 days left never fires (above the configured max threshold of 30d).

**Per-(cert, threshold) ledger** in the new `cert_expiration_notifications` table (UNIQUE on `certificate_id, threshold_days`). On send success the row stamps `status='ok'`; on send failure it stamps `status='failed'` and the next sweep upgrades the row to `ok` on retry success. The ledger snapshots `recipients_csv` and `days_to_expiry` at send time so the historical view at `/tls/expirations/notifications` is honest even if the SMTP config or cert lineage later change.

**Alert email body** is multipart-alternative (text + HTML), Message-ID anchored at the sender's domain to keep spam scanners happy. Per-source "Next steps" block: PFX certs link the operator to `/tls/certificates/import-pfx`; DNS-01 wildcards explain the manual-DNS dance; HTTP-01 LE certs point at LE.3 + the certbot log tail. Subject line carries urgency text — `expires in N day(s)`, `EXPIRES TODAY`, `EXPIRED N day(s) ago`. Color-graded badges on the dashboard mirror the urgency: green > 30d, blue 14–30d, yellow 4–14d, red ≤ 3d, hard-red on expired or no-lineage-on-disk.

**Dry-run mode** via `FEA_SMTP_DRY_RUN=1` — every send is short-circuited to a `.eml` file written under `${FEA_SMTP_DRY_RUN_LOG_DIR:-/tmp/fea-smtp}` so the operator can exercise the whole pipeline (threshold detection, body rendering, ledger persistence) without burning real email deliverability. The `webapp/smtp_sender.py` module NEVER opens a socket when the flag is on. The "Send test email" button respects the flag too, with a `(DRY RUN — no email was sent)` suffix on the success flash.

**Modules:** [webapp/smtp_sender.py](webapp/smtp_sender.py) (pure smtplib wrapper, `SmtpSettings` dataclass, `SendResult` outcome dataclass, dry-run impl); [webapp/cert_expirations.py](webapp/cert_expirations.py) (cert view builder, threshold parser, recipient parser, sweep runner, notification recorder). Routes in [webapp/tls_manager.py](webapp/tls_manager.py): `expirations_dashboard` + `expirations_notifications` + `expirations_sweep_now` + `smtp_config` (GET/POST) + `smtp_test`. Templates: [tls/expirations.html](webapp/templates/tls/expirations.html), [tls/smtp.html](webapp/templates/tls/smtp.html), [tls/expiration_notifications.html](webapp/templates/tls/expiration_notifications.html). Sidebar entry "Expirations" under TLS Manager. Two new model classes (`SmtpConfig`, `CertExpirationNotification`) in [webapp/models.py](webapp/models.py) — both created via `db.create_all()` on next boot, no explicit migration phase needed.

### TLS Manager — PFX import (2026-05-31)

Replaces the manual `openssl pkcs12` procedure documented in `docs/PFX2CER.md` with a web UI upload at `/tls/certificates/import-pfx`. Operator picks a `.pfx`/`.p12` file + types the password; FEA parses it in-process via `cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12`, sanity-checks the bundle, and writes the certbot-layout PEM files (`cert.pem`/`chain.pem`/`fullchain.pem`/`privkey.pem`) under `${FEA_PFX_DIR}` (default `/config/imported-certs/<slug>/`). A `ManagedCertificate` row is created with `challenge_type='pfx_import'` and stamped with the active `domain_id`. The existing `/tls/deploy` pipeline reads `<lineage>/fullchain.pem` + `privkey.pem` from disk so PFX-imported certs slot in unchanged — no SMC API change, no deployer change. Operator clicks Deploy on the imported cert and the 5-step TLS pipeline runs identically to LE-issued certs.

**Refusals.** The import handler refuses with a specific operator-facing flash for each known failure mode: wrong password (`Could not decrypt PFX — wrong password, or the file is not a valid PKCS#12 bundle`), missing private key, missing leaf cert, key/cert public-key mismatch, already-expired cert (`Certificate already expired on YYYY-MM-DD. Re-issue the cert and re-export the PFX before importing.`), and clobbering an existing Let's Encrypt-tracked row (`Untrack it first… re-importing would conflict with the LE lifecycle`). The expiry check happens BEFORE any DB row is created so an old PFX can't poison the cert list.

**Reimport idempotency.** Re-uploading a PFX with the same CN replaces the on-disk PEM files + refreshes `last_cert_hash`/`last_checked_at` in place — no duplicate DB row. The flash message reads `PFX reimported for <domain>`. Existing `TLSDeployment` rows keep pointing at the same `certificate_id`; the operator clicks Deploy again to push the renewed cert to engines. PFX rows are intentionally excluded from the LE.3 lazy-sweep renewal scheduler (the sweep filters by `challenge_type='http01'`) — renewals are operator-initiated.

**Cert-list visibility.** `_certs_in_active_domain` extended to union (a) certs with a `TLSDeployment` in the Domain (legacy Path I scoping) with (b) certs directly stamped to the Domain via `ManagedCertificate.domain_id`. PFX imports use path (b) so they're visible immediately after upload, before any deployment exists. The certificates list now also carries a per-row "Source" column with badges: blue `PFX`, primary `LE · DNS-01`, secondary `LE · HTTP-01`. The page header gains a green "Import PFX" button next to the title.

**Backup + factory-reset coverage.** `webapp/factory_reset.build_backup_zip()` now walks `${FEA_PFX_DIR}` into the ZIP as `imported-certs/`, alongside the LE state and migration projects. Restore from backup reinstates the PFX PEM files alongside the DB rows that point at them — no re-upload required from the operator. Factory reset wipes `${FEA_PFX_DIR}` alongside the other on-disk artifacts (sginfo, scan logs, webhook tokens) so the box is honest about being empty.

**Refused-clobber rationale.** A row with `challenge_type` in `{http01, dns01_manual}` represents a Let's Encrypt cert with a lineage at `${CERTBOT_CONFIG_DIR}/live/<fqdn>/` that's owned by the LE renewal lifecycle. Letting a PFX import silently rewrite `certbot_lineage` to a different on-disk path would orphan the LE files and break the LE.3 sweep's reissue path. The refusal forces the operator to explicitly untrack the LE row first — making the lifecycle handoff a deliberate decision.

Modules: [webapp/pfx_import.py](webapp/pfx_import.py) (parse + save + slug helpers + `PfxImportError`); routes: `certificates_import_pfx` + `_certs_in_active_domain` extension in [webapp/tls_manager.py](webapp/tls_manager.py); template: [webapp/templates/tls/import_pfx.html](webapp/templates/tls/import_pfx.html); cert list tweaks: [webapp/templates/tls/certificates.html](webapp/templates/tls/certificates.html); backup + reset coverage: [webapp/factory_reset.py](webapp/factory_reset.py).

### Roadmap item 5 — Let's Encrypt completion: LE.3 + LE.4 + LE.5 + LE hygiene (2026-05-29)

The three remaining LE phases all landed in one session, plus a hygiene batch surfaced during the LE review. Five distinct commits — separated so each phase's diff stays reviewable in isolation. Operator answers (LE-Q1 through LE-Q5 in [TODO.md](TODO.md)) locked the design before code was cut.

**LE.5.a — Backup completeness patch** (commit `2811947`, operator answer LE-Q5=B). `webapp.admin.backup()` now downloads a full deployment snapshot — `flexedge.db` + `encryption.key` + the entire `/config/letsencrypt/{accounts,live,archive,renewal}/` tree + `data/projects/`. Restore is reissue-free for LE certs and preserves in-flight FortiGate migrations. Two backup-completeness gaps (LE accounts from the LE design Q12, V1's `data/projects/`) closed in one commit. `webapp.factory_reset.build_backup_zip()` refactored with a parameterized prefix so both `/admin/backup` and the pre-factory-reset snapshot path share the same code. Per-file failures log + swallow so one unreadable symlink doesn't abort the snapshot. Excluded by design: `letsencrypt/work` + `letsencrypt/logs` (transient state) and `.env` (operator-supplied secrets — recreate from `config/.env.example` after restore). Docs: [CLAUDE.md] backup-strategy line rewritten with the actual content; [docs/deployment-guide.md] backup table + Methods + Restore sections all updated.

**LE.5.b — Revoke UI** (commit `8c77b5d`, operator answer LE-Q3=B). Wires the existing `cert_revoke` queue handler (implemented since LE.1, never reachable from UI) to a "Revoke at LE" button on the cert detail page. Distinct from "Stop tracking" — revoke publishes the cert's serial to LE's CRL/OCSP responders so browsers/engines that check revocation stop trusting it; Stop tracking only drops the FEA row and leaves the cert valid at LE until natural expiry. Modal with reason picker (`unspecified` / `keyCompromise` / `superseded` / `cessationOfOperation` / `affiliationChanged` — RFC 5280 subset). Optional chain checkbox "Also stop tracking in FEA after revoke" runs both actions in one click; the chain fires INSIDE the queue handler after the revoke succeeds (post-route ORM delete would race the async worker). New `POST /tls/letsencrypt/<id>/revoke` route gated to active certs only. `enqueue_cert_revoke` gained the `also_stop_tracking` kwarg; `_handle_cert_revoke` honors the chain via `db.session.delete(cert)` after a successful certbot revoke. PendingChange FK is `ondelete=SET NULL` so the chain doesn't dangle.

**LE hygiene** (commit `07f6c82`, operator answer LE-Q4=B). Four small fixes surfaced during the LE review, bundled as a separate commit between LE.5 and LE.3 so each phase's diff stays focused:

- `cert_delete` (Stop tracking) now auto-aborts the linked PendingChange when it's still in `queued`/`conflict` state via `shared.queue_runner.abort_one()`. Closes the gap where the queue row would later resolve `certificate_id` to "not found" and no-op silently. `push_failed`/`applied` rows are terminal-ish (no race) and rely on the existing FK `ondelete=SET NULL` cascade.
- `AcmeAccount.is_staging` toggle gated to Super Admin. The account is singleton (Q3=A) and flipping `is_staging` changes which LE endpoint EVERY Domain's cert ops hit. Domain Admins can still edit email; the staging checkbox renders disabled with a "Super Admin only" badge + a hidden input re-posts the existing value to keep the form contract honest. Server-side guard in `account_view` POST backs it up.
- Gunicorn `--timeout` bumped from `120` to `360` in [docker/Dockerfile](docker/Dockerfile). First-time ACME account registration via certbot can block up to 300s (`DEFAULT_TIMEOUT_S`); the prior 120s default would 504 mid-flow. `account_view` POST also logs a `WARNING` at the moment the operator triggers the slow path so the constraint shows up in `make logs` exactly when relevant.
- `webapp/certbot_reader.py` docstring corrected from `/etc/letsencrypt/` to `${CERTBOT_LIVE_DIR}` (default `/config/letsencrypt/live` since the LE.2 hotfix). Misleading future archaeologists into thinking certbot still wrote to root-owned `/etc/` inside the container.

**LE.3 — Renewal scheduler (lazy-sweep variant)** (commit `9d7bde4`, operator answers LE-Q1=A, LE-Q2=C). New [webapp/letsencrypt_scheduler.py](webapp/letsencrypt_scheduler.py) is THE renewal orchestrator going forward (LE-Q1=A — the certbot host-cron path retained as legacy/fallback). `ensure_lazy_renewal_sweep()` guarded by `was_swept_recently()` reading `platform_settings` key `letsencrypt_last_sweep_at` (default interval 1h — same pattern as `scan_history/retention`). `sweep_due_renewals()` walks `ManagedCertificate.query.filter(status='active', challenge_type='http01', next_renewal_after <= now + 7d)`. For each due cert: `enqueue_cert_renew` → `try_auto_push_for_admins`. Reuses the exact bypass/sync push routing the operator-clicked Force renew button uses, so observable behavior is identical. `SweepReport` dataclass with per-state counters (`candidates_considered`, `enqueued`, `skipped_in_flight`, `skipped_missing_lineage`, `errored`) for audit + flash. Idempotency: certs with an in-flight `pending_change_id` in queued|pushing state are skipped — the next sweep retries automatically because the `cert_renew` handler keeps `status='active'` on push_failed. Cross-Domain scope: single sweep walks every Domain's active certs (same E2 exception as the existing renewal webhook). Wired into `list_certs` so every visit to `/tls/letsencrypt` triggers the gate; failures log + swallow so the cert list still renders even if the scheduler is unhealthy. Host-cron path explicitly marked legacy: `/tls/hook` page gains a yellow "Legacy path since LE.3" banner pointing at LE.3; `tls_scheduler.handle_renewal_webhook` docstring updated to spell out its new fallback role. Closes audit M9 for LE certs as a byproduct.

**LE.4 — DNS-01 wildcards via the acme Python library** (commit `ac4a929`). Heaviest of the LE completion phases — adds support for wildcard certs (`*.example.com`) and any FQDN where serving HTTP on port 80 isn't practical. DNS-01 doesn't fit certbot's single-subprocess model because the operator has to publish a TXT record at THEIR DNS provider mid-flow. New [webapp/letsencrypt_acme.py](webapp/letsencrypt_acme.py) uses the `acme` Python library directly with a state machine: NULL → `awaiting_dns` → `verifying` → `done` | `failed`. Two queue operations connected by the pause:

1. **cert_request (`challenge_type='dns01_manual'` branch)** — opens an ACME order via `start_dns01_order()`, fetches the dns-01 challenge, computes the TXT record name + value, stashes order/authz/challenge URIs + cert private key (base64'd) in `cert.dns_challenge_state` as JSON. Cert stays `status='pending'`, operator UI shows the awaiting-DNS card.
2. **cert_dns_verify (NEW queue op)** — operator clicks "I've published"; handler calls `finalize_dns01_order()` which answers the challenge, polls the authz in 5s ticks up to 3 min, finalizes the order, decodes the cert chain, saves files in certbot layout (`live/` + `archive/` + `renewal/` manual config). On success: `status='active'`, `certbot_lineage` populated, `next_renewal_after` stamped — same shape as a successful HTTP-01 cert.

`start_dns01_order` reconstitutes an `acme.client.ClientV2` from the certbot-stored account credentials (`$CERTBOT_CONFIG_DIR/accounts/.../private_key.json` + `regr.json`). Reuses the singleton account the wizard registered; no duplicate registration. Wildcard handling: TXT record name is `_acme-challenge.<base>` (the wildcard's parent zone), CSR carries the wildcard literally in SAN. `finalize_dns01_order` writes a minimal `renewal/<lineage>.conf` with `authenticator = manual` so `certbot certificates` shows the lineage. New operator-facing diagnostic `precheck_dns_txt()` queries the configured record name via `dnspython` and compares the value — fires before the operator clicks Verify and burns an LE order on a not-yet-propagated record.

Form: FQDN regex relaxed to `^\*?[a-z0-9.\-]+$` (HTML5 affordance — server-side regex is the source of truth and rejects non-wildcard FQDNs with `*` elsewhere). NEW radio: HTTP-01 (default) vs DNS-01 manual, inline help for each. Detail page: NEW awaiting-DNS card (yellow border) shown when state matches, renders the TXT record name + value with Copy buttons each, "Check DNS propagation" pre-check button, "I've published it — continue" submit. Routes: `POST /tls/letsencrypt/<id>/dns-verify`, `POST /tls/letsencrypt/<id>/dns-precheck`.

LE.3 + LE.4 interaction: the lazy-sweep scheduler filters DNS-01 certs OUT (they can't auto-renew without operator action). Force renew on DNS-01 certs reroutes through `cert_request` instead of `cert_renew` so a fresh ACME order opens with a new TXT record — DNS-01 "renewal" is structurally a re-issuance. HTTP-01 certs unchanged.

Schema: no migration needed — the four DNS-01 columns (`challenge_type`, `dns_challenge_state`, `dns_challenge_record_name`, `dns_challenge_record_value`) were preallocated in LE.1's `_phase_le_certs`. New dependencies: `acme>=2.0`, `josepy>=1.14`, `dnspython>=2.4`. First fresh-image build picks them up; existing containers need `pip install -r requirements.txt` or a rebuild.

After these five commits, **roadmap item 5 (Let's Encrypt single-domain CRUD) is complete end-to-end**. HTTP-01 single-FQDN, DNS-01 wildcards, lazy-sweep renewal scheduler, operator-facing revoke UI with optional Stop-tracking chain, and `/admin/backup` that includes the full certbot state for reissue-free restore — all working. The next focus is the two operator-requested TLS features (`.pfx` import + cert-expiration SMTP-alerted dashboard) and the parked caching phase 4 work.

### Verification follow-up Batch V (2026-05-29)

Three findings from the post-rebase `/verify` of commit `934547c` ([TODO.md § Verification follow-ups](TODO.md)). One real production bug + two ergonomics improvements.

**V1 — Migration projects vanish on container recreate.** [webapp/project_manager.py](webapp/project_manager.py) was writing manifests to `Path(__file__).parent / "projects"` → `/app/webapp/projects/` inside the container. [docker/docker-compose.yml](docker/docker-compose.yml) mounts host `data/projects` → `/app/data/projects/` — a different path. The Dockerfile pre-creates `/app/data/projects/` so the bind mount works, but no code ever read or wrote there. **Impact (pre-fix):** every migration project lived in the container's writable overlay; `make update` / image rebuild / Coolify redeploy silently destroyed all in-flight migrations. The host's `data/projects/` directory has been empty since Docker compose landed because of this — verification surfaced it by comparing the code path against the volume mount.

- New `_resolve_projects_dir()` in [webapp/project_manager.py](webapp/project_manager.py) picks `PROJECTS_DIR` at import time in this order: (1) `$FLEXEDGE_PROJECTS_DIR` env override, (2) `/app/data/projects/` when `/app/data/` exists (production Docker — matches the bind mount), (3) `webapp/projects/` legacy fallback for dev/standalone. The detection key is `Path("/app/data").exists()` — present in every Docker deployment (the Dockerfile creates it), absent on non-Docker hosts.
- One-shot bootstrap helper `_migrate_legacy_projects_dir()` wired into [webapp/db_init.py](webapp/db_init.py) at the end of `init_database()`. Moves any pre-V1 project subdirs from `webapp/projects/` into the resolved dir when (a) the resolved dir differs from the legacy dir, (b) the legacy dir has at least one project subdir, (c) the resolved dir is empty of project subdirs. Failures log + swallow, never abort boot. Idempotent — second run finds the resolved dir populated and returns 0.
- Docs: [CLAUDE.md § Project Structure] gains a `data/projects/` entry in the tree; [CLAUDE.md § Encryption] backup-strategy line adds `data/projects/` as a 4th critical artifact; [docs/deployment-guide.md § Backup & Restore] critical-files table adds `data/projects/`, location-by-deployment table extended to show the per-deployment path, and an explicit "Admin Portal → Backup does NOT include `data/projects/`" warning so operators don't assume coverage.

**V2 — CHANGELOG historical entries describe superseded helpers as current.** Pre-May-25 entries describe the now-removed `_load_migration_project_or_redirect` + `domain_slug` approach as the landed state, with no pointer to the 2026-05-25 unification onto `_migration_project_for_domain` + `domain_id`. Future archaeology would trip over the dead helper name. Fix: one-line "Superseded 2026-05-25" footnotes inserted directly under the C1 plaintext-API-key entry and the C2 migration-route gating entry, each pointing forward to "Branch reconciliation rebase (2026-05-25)". The original entries stay intact — historical record preserved with an unmissable forward pointer. Pre-existing markdown lint warnings on TODO.md lines 116/188/345 (trailing whitespace, space-in-emphasis) swept in the same commit.

**V3 — Dev verification ergonomics: no auth bypass for local curl flows.** Verifying authenticated routes from a shell required either a working Azure AD config or Flask test_client + session injection. The May 25 verification had to disable CSRF and inject `session["user"]` inline to reach `/migration/*` — a real Flask request cycle, but not something an external reviewer can replay easily.

- Two-key gated bypass in [webapp/auth.py](webapp/auth.py). New `_maybe_synthesise_dev_session()` activates only when **both** `FLASK_DEBUG=1` AND `FEA_DEV_AUTH_BYPASS_EMAIL=<email>` are set. Synthesises `session["user"] = {email, name="Dev Bypass", oid="dev-bypass-oid", tid=AZURE_TENANT_ID}` on the first authenticated request. Wired into both `login_required` and `profile_required` so authenticated `/migration/*`, `/dhcp/*`, `/tls/*`, `/engines/*`, `/changes/*` all become reachable from `curl` / `httpie`.
- Two-key gate is intentional. A single env var would be too easy to leave on in a Coolify config; requiring `FLASK_DEBUG=1` ties activation to the same flag that already disables `SESSION_COOKIE_SECURE` and other dev affordances.
- Production guards (defense in depth):
  - **Boot banner** in [webapp/app.py](webapp/app.py) emits a multi-line `WARNING` log when the bypass is active: `"DEV AUTH BYPASS IS ACTIVE — Entra ID login is SKIPPED. Every request becomes user=<email>. NEVER ship a production image with this on."` Visible in `make logs`, container stdout, or any log aggregator.
  - **Per-request audit** — every synthesised session emits a `WARNING` line naming the email + route. Accidental activation shows up immediately in audit logs.
  - **Setup wizard refusal** in [webapp/setup.py](webapp/setup.py) — `/setup` returns HTTP 503 + flash when the bypass is active. A bypassed login can't write itself in as Super Admin.
  - **Docker default** — `FLASK_DEBUG=0` is baked into the Docker image. Activating the bypass requires explicitly overriding it in `.env` or compose, which is a deliberate operator action.
- New module-level helper `dev_auth_bypass_is_active()` exported for the setup-wizard refusal and anyone else who needs to gate UI on the bypass state.
- Docs: new "Local verification without Azure AD" section in [docs/deployment-guide.md](docs/deployment-guide.md) with activation steps, the boot banner sample, and all four production guards spelled out. CSRF disable for `curl` POST flows deferred as a follow-up — the test client path covers it for now.

**Files changed**: [webapp/auth.py](webapp/auth.py), [webapp/app.py](webapp/app.py), [webapp/setup.py](webapp/setup.py), [webapp/project_manager.py](webapp/project_manager.py), [webapp/db_init.py](webapp/db_init.py), [CLAUDE.md](CLAUDE.md), [TODO.md](TODO.md), [docs/deployment-guide.md](docs/deployment-guide.md). All Python files AST-parse clean.

### Branch reconciliation rebase (2026-05-25)

Local May 25 work (Let's Encrypt CRUD, Batch G/H job runners, vendored Bootstrap assets, ~9.8k lines net) was developed in parallel with the May 20 remote commits (factory_reset feature, admin/api_keys.html, terminal/cache audit fixes). Reconciled by rebasing the May 25 commit on top of `origin/main` (May 20 commits). 22 conflict hunks across 9 files resolved; the rebased commit is `08b4c71`.

**Reconciliation decisions**:

- **Migration helper** unified on `_migration_project_for_domain(project_id, mutating=…)` (the helper that survived auto-merge and was used by 8 routes). The duplicate `_load_migration_project_or_redirect` helper from local was removed and its 6 call sites updated. Project manifests carry `domain_id` (int) — not `domain_slug` — so the unified helper's `domain_id != g.domain.id` check is the single source of truth.
- **Browser SSH terminal C4 fix** kept the May 20 implementation (close code **4404** matching the "not found" code so credential existence in other Domains isn't leaked; `_active_domain_id_for_ws()` helper to resolve the active Domain reliably from the session profile because Flask-Sock handshakes don't reliably populate `g.domain`). The local May 25 variant used 4403 and read `g.domain` directly — superseded.
- **SMC cache C5 fix** kept the May 25 implementation: cache entries stay 2-tuple `(data, cached_at)`; the new `peek(section, key_parts)` and `list_sections()` helpers replace the previous direct `_section_caches.items()` walk in the quick-search endpoint. Cross-Domain leaks are impossible by construction (only canonical `(active_domain.id, …)` keys get peeked). The May 20 3-tuple variant `(data, cached_at, domain_id)` was retired.
- **SMC cache H12 — in-flight coalescing**: new module-level `_inflight: dict[cache_key, Future]` + `_inflight_lock` coalesces concurrent non-`refresh` misses on the same key. Leader runs the fetcher, followers block on `Future.result()` — eliminates the gunicorn thread starvation that used to occur on cold-cache fan-in (8/16 threads queueing behind one SMC fetch). New `coalesced` and `inflight_now` counters in `stats()`.
- **Webhook bearer-token check (C6+M15)**: both `tls_manager.py` and `dhcp_manager.py` `require_api_token` decorators end up with the single 503-on-empty guard (no duplicate) + `hmac.compare_digest(presented.encode("utf-8"), configured.encode("utf-8"))`.

**Docs aligned to the rebased code state**:

- [CLAUDE.md § SMC read cache] cache-tuple description corrected (2-tuple, not 3-tuple); H12 coalescing added; bogus `dhcp_hosts_by_subnet` accessor row removed (no such accessor exists in `webapp/domain_objects.py`).
- [CLAUDE.md § Migration Manager § Domain isolation] route-decorator section rewritten — all routes are `@domain_admin_required` (none stay `@login_required`); both mutating and read-only routes go through `_migration_project_for_domain`.
- [TODO.md C2] rewritten to reflect the unified `_migration_project_for_domain` + `domain_id` scheme.
- [TODO.md C4] close code corrected to **4404** (not 4403) and the rationale documented; `_active_domain_id_for_ws()` helper noted.
- [docs/CachingReview.md O1] quick-search row updated — `peek`/`list_sections` replace the old `walks _section_caches` description.

### Roadmap item 5 — Let's Encrypt CRUD: Phases LE.1 + LE.2 + read-only-FS hotfix (2026-05-11)

**Hotfix (same day, after operator first-run test):** the initial LE.2 build invoked certbot with its compiled-in defaults (`/etc/letsencrypt/`, `/var/lib/letsencrypt/`, `/var/log/letsencrypt/`), all of which are owned by root inside the Docker image and unwritable by the unprivileged gunicorn process. Operator's first `/tls/letsencrypt/account` submit failed instantly with `[Errno 30] Read-only file system: '/etc/letsencrypt/.certbot.lock'`. Fix: every certbot invocation in [webapp/letsencrypt_certbot.py](webapp/letsencrypt_certbot.py) now passes explicit `--config-dir /config/letsencrypt`, `--work-dir /config/letsencrypt-work`, `--logs-dir /config/letsencrypt-logs` (all overridable via env vars). The `/config/` bind-mount is the existing writable volume used by every FEA deployment and is what `/admin/backup` already includes, so the account key + cert lineage back up with the rest of FEA state automatically (Q12). The legacy `CERTBOT_LIVE_DIR` config in `app.py` now defaults to `/config/letsencrypt/live` to match (existing host-mounted certbot lineages from operators who ran certbot outside the container can be recovered by setting `CERTBOT_LIVE_DIR=/etc/letsencrypt/live` in `.env`). The default `CERTBOT_WEBROOT` also moved to `/config/letsencrypt-webroot` for the same reason. New helper `ensure_certbot_dirs()` creates the three directories lazily on first use.

Web UI inside FEA that drives certbot end-to-end. Operator opens `/tls/letsencrypt`, accepts the Let's Encrypt ToS once (account-setup wizard), configures the per-Domain glob allowlist, then requests a cert by FQDN. The request flows through the change-management queue (Phase E.2 pattern); Domain Admins or operators with the new `letsencrypt` bypass feature get instant auto-push with a watcher card on the cert detail page. On success the cert lands at `/etc/letsencrypt/live/<fqdn>/` and the existing TLS Manager deploy pipeline picks it up unchanged — first-time issuance still requires a manual `/tls/deploy` step to bind the cert to engines (Q8 lean: only renewals auto-deploy).

Design questionnaire ([docs/LetsEncryptDesign.md](docs/LetsEncryptDesign.md)) answered by operator on 2026-05-11; 16 decisions locked. Implementation followed the Phase E.2 + scan_jobs patterns established by Batches G–H.

**New schema.** New `acme_accounts` (singleton — Q3) and `domain_cert_patterns` (per-FEA-Domain glob allowlist — Q6+Q6a) tables, both empty on fresh install. Extensions to `managed_certificates`: `domain_id`, `requested_by_user_id`, `status`, `last_error`, `is_staging`, `pending_change_id` FK, `next_renewal_after`, `account_id` FK, plus four `dns_challenge_*` columns preallocated for Phase LE.4 (manual DNS-01 wildcards). Migration `_phase_le_certs` in [webapp/db_init.py](webapp/db_init.py) is idempotent — `PRAGMA table_info` guard before each `ALTER TABLE ADD COLUMN`. Index `ix_managed_certificates_next_renewal` lands ahead of the Phase LE.3 scheduler so the "due soon" query is cheap from day one.

**New modules.**

- [webapp/letsencrypt_certbot.py](webapp/letsencrypt_certbot.py) — pure subprocess wrappers. `register_account()`, `request_certificate()`, `renew_certificate()`, `revoke_certificate()`. No Flask context, no DB; the queue handler and the scan_jobs runner both call into here so the actual `certbot` invocation lives in one tested place. `CertbotResult` dataclass captures success / lineage / next_renewal_after / stdout+stderr tails / duration / exit code. 5-minute default timeout; renewal window 60 days from issuance (90-day cert validity minus LE's 30-day recommended renewal lead).
- [webapp/letsencrypt_allowlist.py](webapp/letsencrypt_allowlist.py) — pure glob-matcher. `is_valid_pattern()` refuses `*`, `*.com`, uppercase, whitespace, and any pattern with no `.` (too permissive). `matches_any_pattern()` uses `fnmatch.fnmatchcase` so operator mental model is shell-glob. `is_fqdn_allowed_for_domain()` enforces "no patterns configured = nothing allowed" safe default. Smoke-tested 9 cases pass.
- [webapp/letsencrypt_jobs.py](webapp/letsencrypt_jobs.py) — scan_jobs runner. Mirrors `webapp/tls_deploy_jobs.py` exactly; captures `current_app`, spawns daemon thread, calls `push_one()` inside `app_context()`, handles bypass-cleanup with audit marker.
- [webapp/letsencrypt_queue.py](webapp/letsencrypt_queue.py) — `enqueue_cert_request()` / `enqueue_cert_renew()` / `enqueue_cert_revoke()` + `try_auto_push_for_admins()` (returns `(spawned, scan_id)` for the watcher-redirect path).
- [webapp/letsencrypt_manager.py](webapp/letsencrypt_manager.py) — Flask Blueprint at `/tls/letsencrypt/*` (Domain Admin or higher). Routes: `/` list, `/new` request form, `/<id>` detail with watcher card, `/<id>/renew` force-renew, `/<id>/delete` stop-tracking, `/<id>/status` JSON poll, `/account` setup wizard / edit, `/patterns` allowlist management. Also a separate public blueprint `acme_challenge_bp` serving `/.well-known/acme-challenge/<token>` for LE's HTTP-01 validation (alphanumeric-only token guard + resolve-inside-webroot check, no auth — LE's validators have no session).

**New queue handlers** in [shared/queue_runner.py](shared/queue_runner.py): `cert_request`, `cert_renew`, `cert_revoke` (Q6c discrete-ops shape). The cert_request handler defensively re-checks the allowlist before invoking certbot (defence against payload tampering between enqueue and push). The SMC session opened by `push_one()` is unused — cert ops don't talk to SMC — but the handler shape stays uniform with other writers.

**New templates** under [webapp/templates/tls/letsencrypt/](webapp/templates/tls/letsencrypt/): `account.html` (setup wizard / edit), `list.html` (cert list), `new.html` (request form with inline allowlist display), `detail.html` (cert detail + watcher card during cert ops + last-error display), `patterns.html` (allowlist add/remove UI).

**Wiring.** Sidebar entry "Let's Encrypt" added under the TLS Manager section in [webapp/templates/base.html](webapp/templates/base.html). New `letsencrypt` bypass feature in [shared/queue_settings.py](shared/queue_settings.py) (operator-managed via Admin Portal → Bypass capability matrix). Feature `letsencrypt` registered for `platform_logs` filtering in [webapp/app.py](webapp/app.py). Certbot is already in the Docker image (`apt-get install certbot`).

**HTTP-01 deployment.** nginx/Traefik in front of FEA MUST forward `/.well-known/acme-challenge/*` to FEA's gunicorn — a one-line `location` block. FEA serves the challenge file from `CERTBOT_WEBROOT` (default `/var/www/certbot`) which certbot writes to during the cert request. No shared volume between containers needed.

**Pending phases** (operator will test LE.1+LE.2 then close session):

- **LE.3** — renewal scheduler (background thread, hourly tick, enqueue `cert_renew` for any cert with `next_renewal_after < now+7days`); auto-redeploy via existing TLS Manager pipeline.
- **LE.4** — manual DNS-01 via `acme` Python library (Q11); unlocks wildcards. The DNS challenge columns on `managed_certificates` and the `challenge_type` field already exist.
- **LE.5** — revoke UI + `/admin/backup` includes `/etc/letsencrypt/accounts/`.

### Roadmap item 3 — Policies dedupe + NAT policies surfaced (Batch J, 2026-05-11)

Closes the operator's locked-in roadmap item from [TODO.md:96](TODO.md). Two surfaces had been competing for "the policies list" — a cards-grid at `/policies` (linked from Navigation sidebar + dashboard "Policy Viewer" card) and a table at `/browse/fw_policies` (linked from Infrastructure sidebar + dashboard element grid). Same SMC data, different rendering, no functional reason for both. Operator picked Infrastructure as canonical; this batch removes the duplicate and adds the NAT-policy visibility the operator was missing.

**Dedupe — Infrastructure wins.**

- [webapp/app.py](webapp/app.py) `policies()` now 302-redirects to `/browse/fw_policies`, preserving any querystring (so a `?refresh=1` operator action still hits the target). Bookmarks to `/policies` keep working; the old cards-grid template `webapp/templates/policies.html` was deleted as dead code.
- [webapp/templates/base.html](webapp/templates/base.html) — Navigation → Policies sidebar entry removed. The Infrastructure → Firewall Policies entry stays put.
- [webapp/templates/index.html](webapp/templates/index.html) — dashboard "Policy Viewer" special card removed; `fw_policies` is already in the dashboard element grid above (one row per element type) so the special card was always redundant.

**NAT policies — surfaced via per-policy rule counts.**

Forcepoint SMC has no standalone NATPolicy element type (confirmed against `fp-NGFW-SMC-python` SDK — only `FirewallPolicy` is exposed via `smc.policy.layer3`; NAT rules are an inner collection `fw_ipv4_nat_rules` on each FirewallPolicy). So the operator's "add NAT policies to the list" request maps to "show how many NAT rules each policy contains" alongside the access-rule count, exactly how the SMC Management Client surfaces them in its own policy listing.

- [webapp/smc_client.py](webapp/smc_client.py) `list_policies()` and `list_elements("fw_policies", ...)` now return `fw_rule_count` + `nat_rule_count` per row. Counting iterates the lazy SMC rule collections (one round-trip each) so it's expensive on cold cache — but the result lands in the standard `policy_list` (Loose 24h) / `element_list.fw_policies` (Quick 1h) cache sections, so subsequent renders are free, and the queue runner's existing post-push invalidation hooks already drop both sections after any policy mutation. Per-policy count failures don't abort the listing — that row just gets `None` and the template renders a `?` badge.
- [webapp/templates/browse.html](webapp/templates/browse.html) — new `fw_policies` branch with two new columns: **FW rules** (blue badge with count, grey for 0) and **NAT rules** (yellow badge when `>0`, grey for `0`, `?` when count unavailable). Row name + action button now link directly to `/policy/<name>` rules viewer (which already shows both FW + NAT rule lists in tabs) instead of the generic `/detail/fw_policies/<name>` element page — that detail page added no value over the rules viewer for policies.

Operator now scans the policy list and sees at a glance which policies carry NAT translation work. One click reaches the existing rules viewer that already had both rule types side-by-side. No new top-level NAT route, no schema changes, no SDK dependency churn.

### Security audit Batch I — N+1 queries, pagination, vendored Bootstrap (2026-05-09)

Three Medium polish wins from [TODO.md § Security & efficiency audit](TODO.md) — M7, M11, M13. Operator-visible perf + offline-readiness wins; no security-criticality. Together they close the "is this page going to take 5 seconds to render once we have a year of data?" question for the three lists that grow unbounded over time, plus the "what happens if our customer site has no internet?" question for the UI.

**M7 — N+1 query hotspots.** Three sites fixed with `joinedload` / `selectinload` / batched `IN`:

- [webapp/dhcp_manager.py](webapp/dhcp_manager.py) `credentials_list` — `accesses` query now eager-loads `domain → api_key` via `joinedload(DhcpEngineSshAccess.domain).joinedload(Domain.api_key)`, killing the per-row source-IP-drift lazy SELECT loop.
- [webapp/changes.py](webapp/changes.py) `index` — conflict-peer lookup now batched into one `IN` query (was one `db.session.get` per conflict row); 100-conflict queue drops from 100 round-trips to 1.
- [webapp/admin.py](webapp/admin.py) `users` — `User.query` now `selectinload(User.domain_accesses).joinedload(UserDomainAccess.domain)` so the template's `{% for access in u.domain_accesses %}{{ access.domain.display_name }}` loop doesn't fire N×M SELECTs.

**M13 — Pagination on the two heaviest-blast-radius lists.** Pattern lifted from `scan_history/routes.py:94-106` (50-row pages + `?page=` + `total_pages` for the pager):

- [webapp/changes.py](webapp/changes.py) `index` was hard-capped at `limit(500)` with a "narrow your filter" footer that made older rows unreachable on busy queues. Now paginated end-to-end; [webapp/templates/changes/index.html](webapp/templates/changes/index.html) renders a Prev/Page X of Y/Next pager that carries every existing filter querystring through.
- [webapp/dhcp_manager.py](webapp/dhcp_manager.py) `scope_detail` reservations now paginated (50/page). Big DHCP scopes (1000+ reservations) render instantly with operator-controllable page navigation. [webapp/templates/dhcp/scope_detail.html](webapp/templates/dhcp/scope_detail.html) gets a matching pager at the bottom of the reservations card.
- The other two M13 candidates (scopes list — typically <50 per Domain; leases viewer — bounded by subnet size, sort-critical for diagnostics) were left intentionally; pagination would hurt more than help.

**M11 — Vendor Bootstrap locally.** Bootstrap 5.3.3 (CSS + bundled JS) and bootstrap-icons 1.11.3 (CSS + woff + woff2) now under `webapp/static/vendor/bootstrap/` and `webapp/static/vendor/bootstrap-icons/`. [webapp/templates/base.html](webapp/templates/base.html) references each via `url_for('static', ...)?v={{ app_version }}` so a new release auto-busts the browser cache. New context-processor key `app_version` exposed from [webapp/app.py](webapp/app.py) `inject_globals` — derives from `_build_version["commit"]` so it changes every deploy. New helper [scripts/vendor-assets.sh](scripts/vendor-assets.sh) re-downloads from jsdelivr after a Bootstrap upgrade (version pins at top of the script) and asserts the CSS still uses `fonts/` relative paths so a future upstream layout change fails loud. Offline / air-gapped / firewalled customer deployments now render the UI without any internet round-trip at runtime — closing the "feedback_deployment_scenarios" standing rule.

### Security audit Batch H — cache stampede + 5 medium-tier wins (2026-05-09)

Six fixes resolved together — H12, M3, M4, M5, M8, M19 from [TODO.md § Security & efficiency audit](TODO.md). Independent surface-area changes; bundled because each is small.

**H12 — Cache stampede coalescing.** [shared/smc_cache.py](shared/smc_cache.py) `cache_get_or_fetch` now coalesces concurrent non-refresh misses on the same key. New module-level `_inflight: dict[cache_key, Future]` + `_inflight_lock`: the first arrival claims a `concurrent.futures.Future`, runs the fetcher, sets the result, and clears the slot; followers block on `Future.result()` and pick up the same payload (or the same exception). On the cold-cache fan-in pattern that was burning 8/16 gunicorn threads behind one SMC fetch, the wasted threads drop to zero — only the leader does network I/O. `refresh=True` always does its own fetch (explicit invalidations should not wait on a possibly-stale leader's call). New `coalesced` + `inflight_now` counters in `stats()` for diagnostics. Followers re-check the section cache before blocking on the Future, so the case where the leader finishes between our two locks serves from cache instead of waiting unnecessarily.

**M3 — TLS renewal hook script + token split.** [webapp/tls_scheduler.py](webapp/tls_scheduler.py) `install_deploy_hook` now writes TWO files: the hook script (`chmod 0700` — was 0755) and a sibling `flexedge-tls-renew.sh.token` (`chmod 0600`) the script `source`s at runtime to import `FLEXEDGE_TLS_API_TOKEN`. Atomic write order: token file `touch+chmod 0600` BEFORE write_text to avoid a brief 0644 window. New `generate_token_file()` helper + `DEFAULT_TOKEN_FILE` constant. The /tls/hook page ([webapp/templates/tls/hook.html](webapp/templates/tls/hook.html)) now shows BOTH files with separate Copy buttons + path labels — manual installers (operators on hosts where the auto-installer can't reach `/etc/letsencrypt/renewal-hooks/deploy/`) save each block to disk with the correct permissions.

**M4 — Content-Disposition filename sanitiser.** New helper [shared/csv_safe.py](shared/csv_safe.py) `safe_filename(name, default)` strips CR / LF / TAB / `"` / `\\` / leading dot from any candidate filename, replaces `/` with `_`, and caps at 200 chars (falls back to `default` on empty). Wired into all three `Content-Disposition` interpolation sites: `tools_scan_csv`, the sgInfo file download (both in [webapp/engines_manager.py](webapp/engines_manager.py)), and `scan_history.export_csv` ([webapp/scan_history/routes.py](webapp/scan_history/routes.py)). Hostile SMC element names with embedded quotes / CRLF can no longer break the header structure or inject extra headers.

**M5 — Audit-marker email sanitiser.** New helper [webapp/smc_audit_marker.py](webapp/smc_audit_marker.py) `_sanitize_user_email()` strips terminator characters (whitespace + `]`) and caps length at 256. `pack_audit_into_comment` now wraps `_resolve_user_email()` in the sanitiser. A weaponised email like `attacker@e ] [flexedge:audit user=admin]` can no longer plant a forged marker in adjacent comment text after passing through the SMC `comment` round-trip. Empty / sanitised-to-empty input falls back to `system` — same fallback as the original resolver.

**M8 — Composite log index.** Composite index `ix_platform_logs_domain_ts` declared on the `PlatformLog` model ([webapp/models.py](webapp/models.py)) so `db.create_all()` picks it up on fresh installs; the redundant standalone `domain_id` index was dropped. New migration `_phase_audit_indexes` in [webapp/db_init.py](webapp/db_init.py) issues `CREATE INDEX IF NOT EXISTS` against existing DBs (idempotent — safe to run on every boot). The /logs viewer's `WHERE domain_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC` query now satisfies the predicate AND the order in one index scan.

**M19 — Single grouped count on changes index.** [webapp/changes.py](webapp/changes.py) `index` route now consolidates all 7 per-state counts (queued / pushing / conflict / push_failed / pushed / applied / aborted) into a single `with_entities(state, func.count(id)).group_by(state)` query, then projects into the existing `stats` dict via `dict.get(state, 0)`. On a 5000-row queue accumulated over a quarter, the page render drops from 7 sequential round-trips to 1.

### Security audit Batch G — async-ify the four blocking SMC operations (2026-05-09)

Resolves audit items H4, H6, H7, H8 from [TODO.md § Security & efficiency audit](TODO.md). Each was burning 30s-2min of an HTTP request thread and (for H8) holding the SMC global lock, freezing every other operator on the box. All four now return instantly and run in a daemon thread; the originating page renders a watcher card that polls a JSON status endpoint and reloads when done. Same scan_jobs runtime that already powers the engine + DHCP scan tools — three new feature glue modules (`webapp/drift_jobs.py`, `webapp/dhcp_deploy_jobs.py`, `webapp/tls_deploy_jobs.py`) all follow the `dhcp_scan_jobs` / `engine_scan_jobs` pattern of: register-job → capture `current_app` → spawn daemon thread → run inside `app_context()` → mark_done.

**H4 — DHCP lease viewer cache + parallel fetch.** [webapp/dhcp_manager.py](webapp/dhcp_manager.py) `scope_leases` now fans out per-node SSH reads via `ThreadPoolExecutor(max_workers=8)` and wraps each fetch in `cache_get_or_fetch(section="dhcp.leases", key_parts=(domain_id, engine_name, node_index), ttl=120)`. 4-node cluster on cold cache: 4 parallel SSH reads (≈ 2-4s wall-clock instead of 10-15s sequential); on warm cache: instant. `?refresh=1` query param drops the cache for forced re-read; the existing Refresh button now passes it. Freshness badge in [webapp/templates/dhcp/leases.html](webapp/templates/dhcp/leases.html) — green "fresh" when every node was just re-fetched, grey "cached · Ns ago" using the OLDEST cached_at across all nodes (worst-case staleness). Activity log only fires on cache misses.

**H6 — Drift scan via scan_jobs.** [shared/smc_drift.py](shared/smc_drift.py) `scan_domain_drift` now accepts an optional `progress_cb(checked, total, smc_name, smc_type, state)` invoked after every row. New thin glue [webapp/drift_jobs.py](webapp/drift_jobs.py) registers a `feature="changes"` job, captures `current_app` for the worker thread, re-resolves the Domain inside an `app_context()`, and routes per-row events through `update_progress` / `increment_extra` / `append_log`. `POST /changes/drift/scan` now spawns the daemon thread and 302-redirects to `/changes/drift?scan_id=X` immediately; `drift_index` reads `?scan_id` and renders a watcher card with progress bar + per-state counters (clean / drifted / gone / errored / skipped) + 10-line live log. New JSON poll endpoint `GET /changes/drift/scan/status?id=X`. On done, the page reloads and consumes the report (flash with summary).

**H7 — DHCP scope deploy via scan_jobs.** [webapp/dhcp_pusher.py](webapp/dhcp_pusher.py) `push_scope_to_engine` + `_push_scope_to_engine_locked` now accept an optional `progress_cb(*, phase, node_index, node_hostname, total_nodes, done_nodes, node_result=None)`. Phase=`start` fires when each node's SSH connection begins; `done` fires after the per-node write+verify with the full `NodeResult`. New thin glue [webapp/dhcp_deploy_jobs.py](webapp/dhcp_deploy_jobs.py) wraps the call in a daemon thread inside `app_context()`. `_run_push` (handles `/scopes/<id>/deploy` + `/resync`) spawns the job and 302-redirects to `scope_detail?deploy_scan_id=X`. `scope_detail` renders a watcher card with progress bar + log tail; new `GET /dhcp/scopes/<id>/deploy/status` is the JSON poll target. On done, page reloads (no `?deploy_scan_id`), consumes the report, and surfaces the same flashes + activity-log rows for ok / partial / failed / blocked + per-node reload-warning details — identical UX to before, just non-blocking. Per-node parallelism intentionally NOT changed (file write order matters within each engine; `engine_op_lock` already serialises per engine).

**H8 — TLS deploy via scan_jobs.** Phase E.2's queue-row pattern was already in place — what was missing was offloading the auto-push from the request thread. New thin glue [webapp/tls_deploy_jobs.py](webapp/tls_deploy_jobs.py) wraps `shared.queue_runner.push_one(change_id)` in a daemon thread inside `app_context()`, captures `is_bypass` so the queue-row cleanup (delete on success + audit marker) lands together with the deploy. [webapp/tls_manager.py](webapp/tls_manager.py) `deploy_execute` POST now creates the queue row + spawns the worker via `tls_deploy_jobs.start_deploy()` and 302-redirects to `?tls_scan_id=X`; the GET handler consumes the report on `state=done` and renders the existing result panel + flashes. New `GET /tls/deploy/<id>/status` JSON poll target. Watcher card on [webapp/templates/tls/deploy_execute.html](webapp/templates/tls/deploy_execute.html) shows step 0 → 5 progress + log tail. The request thread no longer waits 30-60s holding the SMC global lock; concurrent deploys still serialise behind the lock IN THE WORKER but operator HTTP threads stay free for other work.

### Security audit Batch F — SQLite pragmas, CSV-injection, setup race, cookie security (2026-05-09)

Five wins resolved in one batch — H1, H3, H10, M1, M2 from [TODO.md § Security & efficiency audit](TODO.md). Independent fixes; bundled because each is small.

**H1 — SQLite pragmas on every connection.** [webapp/db_init.py](webapp/db_init.py) `_enable_sqlite_foreign_keys` is renamed `_set_sqlite_pragmas` internally and now issues three pragmas instead of one: `PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL`. Default `busy_timeout=0` was the silent killer behind sporadic `database is locked` errors during boot migrations / drift scans / push runner contention; 5s is enough to ride out the longest critical section we have. WAL-mode `synchronous=NORMAL` is ~3× faster than the FULL default and only sacrifices the last in-flight transaction on power loss — acceptable for an admin tool.

**H3 — CSV-injection neutraliser.** New shared helper [shared/csv_safe.py](shared/csv_safe.py) `csv_safe(value)` prepends a `'` (Excel string-mode escape) to any string that begins with `=`, `+`, `-`, `@`, TAB, or CR — neutralising formula execution per OWASP CSV Injection guidance. Wired into both export sites: [webapp/engines_manager.py](webapp/engines_manager.py) `tools_scan_csv` and [webapp/scan_history/routes.py](webapp/scan_history/routes.py) `export_csv` wrap every string-typed cell (`ip`, `mac`, `hostname`, port lists). Hostile reverse-DNS records like `=cmd|'/c calc'!A1` no longer run when the CSV is opened in Excel.

**H10 — Setup wizard race + AAD `tid` verification.** Three layers:

1. [webapp/auth.py](webapp/auth.py) gains `aad_tenant_is_single()` (returns True iff `AZURE_TENANT_ID` is a concrete UUID — `common`/`organizations`/`consumers` placeholders return False) and `verify_aad_tid(userinfo)`. `callback()` now refuses any login whose token's `tid` claim doesn't match the configured tenant. Multi-tenant placeholders fail-closed: the verifier returns False because there's no UUID to match against.
2. [webapp/setup.py](webapp/setup.py) re-gates the wizard on `aad_tenant_is_single()` and uses an atomic single-winner claim. Before creating the User, it inserts a sentinel `PlatformSetting(key="setup_completed", value="1")`; the PK uniqueness constraint gives single-winner semantics — the loser hits `IntegrityError`, rolls back gracefully, and gets bounced to the login page with a clear flash. Belt-and-suspenders re-check on `User.query.count() > 0` catches legacy migrated installs missing the sentinel.
3. [webapp/db_init.py](webapp/db_init.py) `init_database` now also honours the sentinel — `SETUP_REQUIRED` is True iff `user_count == 0 AND sentinel is None`. Manually deleting User rows does NOT re-arm the wizard; recovery requires explicitly removing the `setup_completed` row.

Closes the "first stranger to find /setup becomes Super Admin" hole on multi-tenant misconfigurations and the "two Azure AD users hit /setup simultaneously and both become Super Admin" race under multi-worker gunicorn.

**M1 — `SESSION_COOKIE_SECURE` default ON.** New [webapp/app.py](webapp/app.py) `_session_cookie_secure_default()` returns True by default; off when `FLASK_DEBUG=1` (dev) or `FLEXEDGE_INSECURE_COOKIES=1` (operator override). Production deployments terminate TLS at nginx/traefik upstream of gunicorn so the cookie must be marked `Secure` to keep the browser from leaking it on plain-HTTP fallbacks; `make dev` on port 8088 stays unaffected because `FLASK_DEBUG=1` is set there.

**M2 — Session regeneration on login.** [webapp/auth.py](webapp/auth.py) `callback()` now `session.clear()`s before setting `session["user"]`. The signed-cookie state is re-issued from scratch on every successful Entra ID login — any pre-login fixation attempt's snooped cookie state is worthless. Bonus: drops stale `active_profile` / `active_domain` keys from a previous user on the same browser (e.g. shared kiosks).

### Security audit Batch E — queue runner concurrency (2026-05-09)

Resolves audit items C7, H9, H11 from [TODO.md § Security & efficiency audit](TODO.md). All three are concentrated in [shared/queue_runner.py](shared/queue_runner.py) (with one supporting change to [shared/logging.py](shared/logging.py) and a small UI surface update in [webapp/changes.py](webapp/changes.py) + [webapp/templates/changes/index.html](webapp/templates/changes/index.html)).

**C7 — Atomic state-claim + new transient `pushing` state.** The previous `push_one()` did a read-then-check on `change.state`, then dispatched the SMC handler. Two threads (or a double-clicked Push button, or `push_batch` racing a parallel `push_one` for the same id) both passed the check and both fired the handler. SMC `create` is NOT idempotent — duplicate calls produced duplicate Hosts and conflict errors.

New helpers:

- `_claim_for_push(change_id) -> Optional[str]` — issues `UPDATE pending_changes SET state='pushing' WHERE id=? AND state='queued'` and only proceeds when `rowcount==1`. Returns `None` on lost claim. The transient `'pushing'` state lives between `push_one()` entry and the terminal `_mark_pushed`/`_mark_push_failed` commit.
- `_claim_for_abort(change_id) -> Optional[str]` — same shape for QUEUED|CONFLICT → ABORTED.

`push_one()` now wins-or-skips via `_claim_for_push`. After a successful claim it calls `db.session.expire_all()` and re-reads the ORM row so subsequent commits aren't stale-writes from the pre-claim read. `abort_one()`, `confirm_to_be_deleted()`, and `revoke_to_be_deleted()` all use the same atomic-UPDATE-with-rowcount-check pattern. `_mark_aborted_via_claim` replaces the legacy `_mark_aborted` (which non-atomically read+wrote state) — the helper now expects the atomic claim already happened, and just stamps the row's audit metadata.

**H9 — Audit emit inside the state-transition transaction.** Before this fix, every state-transition primitive did `db.session.commit()` for the state change, then called `_audit(...)` separately. A process kill between those two left a PUSHED row with no audit trail.

[shared/logging.py](shared/logging.py) `audit()` and `op()` now accept a `commit=False` parameter that adds the row to the caller's existing `db.session` without committing. The `_write` exception handler skips its rollback when `commit=False` so it doesn't silently destroy the caller's pending state-change write.

The queue runner's state-transition primitives (`_mark_pushed`, `_mark_push_failed`, `_mark_aborted_via_claim`, `revoke_to_be_deleted`) all use the new pattern: enrol the audit row via `_audit(..., commit=False)`, then `db.session.commit()` once. State change + audit land atomically.

**H11 — Stale-read on `push_batch` (tied to C7).** Implicit fix from C7. With the atomic `UPDATE` claim, a stale ORM-cached row can no longer cause a double-push: either the UPDATE wins (rowcount=1) or it loses (rowcount=0, skip). The `expire_all()` call after each successful claim closes the secondary stale-write window for any subsequent commits in the same `push_one` invocation.

**UI / model surface:** new `pushing` state added to:

- [webapp/changes.py](webapp/changes.py) — included in the "Needs attention" filter (`state="active"`) and the sidebar pending-count badge so a stuck in-flight row from a killed worker is visible immediately. Stats dict gains a `pushing` count.
- [webapp/templates/changes/index.html](webapp/templates/changes/index.html) — adds `Pushing (in flight)` option to the state-filter dropdown.

No DB schema change required — `state` is stored as a string column.

**Files modified (4):** `shared/queue_runner.py`, `shared/logging.py`, `webapp/changes.py`, `webapp/templates/changes/index.html`. All AST-parse clean.

**Known limitation (deferred):** if a worker process is killed while a row is in `'pushing'` state, the row stays stuck. Recovery: an admin can manually flip it back via the UI (now visible in the Active / Pushing filter). A future enhancement could scan on app startup for `'pushing'` rows older than X seconds and either reclaim them (kick to QUEUED) or mark them PUSH_FAILED.

### Security audit Batch D — cross-Domain leaks (2026-05-09)

Resolves audit items C5 and C8 from [TODO.md § Security & efficiency audit](TODO.md). Both close paths where operator-visible content from one Domain could surface in another.

**C5 — Quick-search cache walk leaks element names cross-Domain.** The previous `/api/quick-search` cache walk iterated `_section_caches.items()` directly. Cache keys are SHA-256 prefixes of `(domain.id, …)`, so you can't tell which Domain owns a given entry by inspecting its key — every operator was effectively browsing every Domain's cached element names through the search bar.

Two new helpers in [shared/smc_cache.py](shared/smc_cache.py):

- `peek(section, key_parts) -> Any | None` — return the cached payload for an exact `(section, key_parts)` tuple without triggering a fetch. Returns `None` on miss. Lets callers consume the cache only when they can prove they own the entry.
- `list_sections() -> list[str]` — snapshot of the section names currently registered.

The quick-search walk in [webapp/app.py](webapp/app.py) (`/api/quick-search`) was rewritten to:

1. Resolve the active Domain from `g.domain` (refuse if missing).
2. Build a list of `(section, exact_key, href_resolver, kind)` targets:
   - `engines` keyed `(active.id,)` → results link to `/engines/clusters`.
   - `policy_list` keyed `(active.id,)` → results link to `/policy/<name>`.
   - Every `element_list.<type>` section (enumerated via `list_sections()`) keyed `(active.id, "", "")` → results link to `/browse/<type>`.
3. `peek()` each target. Walk only what we own.

Single-instance detail sections (`element.<type>` / `cluster` / `policy` / `dhcp_host`) are intentionally NOT walked here — their cache keys carry per-instance names we'd have to enumerate ahead of time. Operators usually drill into details from the list-section results anyway. Cross-Domain leaks are zero by construction now.

**C8 — Stored XSS via `|safe` on flash messages.** Twelve templates (`admin/dashboard.html`, `admin/setup.html`, `admin/cache_settings.html`, `admin/log_settings.html`, `auth/login.html`, `optimize/report.html`, `changes/index.html`, `changes/drift.html`, `logs/index.html`, `engines/sginfo_view.html`, `engines/sginfo_history.html`, `engines/tools_scan.html`) rendered flashes as `{{ message|safe }}` / `{{ msg|safe }}`. Combined with f-string flashes that interpolate Domain `display_name`, tenant name, reservation name, etc., a Domain Admin who set `display_name=<img src=x onerror=...>` would land arbitrary JS in any operator's browser via any flash that mentioned the value.

Fix:

- All 12 templates now render `{{ message }}` / `{{ msg }}` — Jinja's default auto-escape kicks in for every dynamic flash interpolation. No code changes needed at the 100+ `flash(f"...")` call sites; auto-escape handles them transparently.
- The one flash caller that legitimately wraps content in HTML — [webapp/auth.py](webapp/auth.py) `<strong>{email}</strong> is not authorised` — uses `Markup("<strong>") + escape(email) + Markup("</strong>") + " is not authorised. ..."`. The `<strong>` styling survives, the (Microsoft-validated but still defense-in-depth) `email` is properly escaped, and `flash()` accepts the resulting `Markup` object so Jinja knows not to re-escape it.

**Files modified (15):** `shared/smc_cache.py`, `webapp/app.py`, `webapp/auth.py`, plus 12 flash-rendering templates. All AST-parse clean. Verification grep confirms no `{{ message|safe }}` / `{{ msg|safe }}` remains anywhere in `webapp/templates/`.

### Security audit Batch C — webhook timing safety (2026-05-09)

Resolves audit items C6 and M15 from [TODO.md § Security & efficiency audit](TODO.md). Both fixes apply to the same `require_api_token` decorator pattern in two network-facing webhook routes — `/tls/api/renew` (certbot deploy-hook) and `/dhcp/api/renew-dhcp` (reserved for future DHCP re-sync hook).

**C6 — Constant-time bearer-token comparison.** Both `require_api_token` decorators ([webapp/tls_manager.py](webapp/tls_manager.py) + [webapp/dhcp_manager.py](webapp/dhcp_manager.py)) used plain `auth[7:] != current_app.config.get("..._API_TOKEN")`. Python string `!=` short-circuits on the first mismatching byte — measurable across enough remote requests to brute-force a token byte-by-byte. Both decorators now use `hmac.compare_digest(presented.encode("utf-8"), configured.encode("utf-8"))` — runtime independent of where the mismatch occurs.

**M15 — Empty-token 503 guard (bundled).** A misconfigured deploy (token-file write failed, env var unset, file permissions blocked) leaves the corresponding `*_API_TOKEN` config as `None`. With the old code, `auth[7:] != None` evaluated true for every request — every webhook caller saw "Invalid token" (HTTP 403), indistinguishable from "wrong token from caller". Both decorators now check `configured = current_app.config.get("..._API_TOKEN") or ""` first; if empty, log an `error`-level message with a clear "Re-create /config/.{tls,dhcp}_api_token and restart" hint and refuse with HTTP 503. Misconfiguration is now unambiguous in operator logs and distinguishable from legitimate auth failures.

**Files modified (2):** `webapp/tls_manager.py`, `webapp/dhcp_manager.py`. Both AST-parse clean.

**Verification grep:** no other bearer-token comparisons in the codebase use plain `!=` — `tls_scheduler.py` references the token only inside the deploy-hook shell-script template (consumer side, not server side). Token storage / display call sites (boot-time `app.config[...] = ...` writes, the renewal-hook script generator) untouched.

### Security audit Batch B — secrets/disclosure (2026-05-09)

Resolves audit items C1 and H2 from [TODO.md § Security & efficiency audit](TODO.md). Both touch the same "where do we store/render API keys" code path — fixed together.

**H2 — Plaintext API key in session cookie.** The Flask session cookie is signed but NOT encrypted; anyone who can read the cookie (XSS, browser extension, support shadowing) recovers the SMC API key. Fix: remove plaintext from the cookie entirely; resolve at runtime from the Domain row.

- [webapp/user_manager.py](webapp/user_manager.py) `_get_profiles_from_db` no longer includes `api_key` in the profile dict it writes to `session["active_profile"]`. Only `tenant` (= `Domain.slug`) which the `_resolve_active_domain` before-request hook uses to populate `g.api_key_obj` per-request.
- New resolver `user_manager.active_api_key_plaintext(profile)` returns plaintext from `g.api_key_obj.decrypted_key`. Falls back to `profile["api_key"]` only when running outside a Flask request context (CLI / JSON-fallback) or when the session predates the upgrade. Single Fernet decrypt per call.
- `get_user_cfg()` (app.py), `_user_cfg()` (engines_manager.py), and the legacy `/select-domain` cfg builder all use the resolver. The DHCP / TLS feature `_smc_cfg(...)` already read from `api_key.decrypted_key` directly (DB row, not session) — already H2-safe.
- `is_active_profile_valid` reworked: was hashing the cached plaintext + looking up `ApiKey.key_hash`. Now uses `Domain.slug → Domain.api_key.is_active` directly. Same revocation-detection behaviour, no plaintext required. Legacy hash check retained as a fallback for non-DB-mode JSON-fallback callers and for any pre-upgrade session that still carries plaintext.
- Plaintext is no longer baked into the session cookie. New cookie size shrinks accordingly.

**C1 — Plaintext API key in migration project files + DOM.** `webapp/project_manager.create_project` was writing the operator-typed SMC API key into `project.json` on disk; `target_config.html` rendered it as `<input value="...">` so anyone with `/migration/<id>/target` access could read it from page source. Fix: stop collecting the field. Migration always runs against the operator's active Domain (already enforced post-C2 by `_load_migration_project_or_redirect`'s `domain_slug` check); the SMC URL / API key / admin domain / verify_ssl all resolve from the active Domain row at runtime.

> **Superseded 2026-05-25.** The `_load_migration_project_or_redirect` helper and the `domain_slug` field on the project manifest were retired during the May 25 branch-reconciliation rebase — the parallel `_migration_project_for_domain` + `domain_id` implementation became the single source of truth. The C1 plaintext-stripping behaviour was preserved; only the helper and manifest field names changed. See "Branch reconciliation rebase (2026-05-25)" entry above.

- [webapp/templates/migration/target_config.html](webapp/templates/migration/target_config.html) — removed the `smc_url`, `api_key`, `domain`, `verify_ssl` inputs. Replaced with a read-only banner showing the active Domain label + SMC URL the migration will run against.
- [webapp/project_manager.py](webapp/project_manager.py) `create_project` default target dict no longer carries `smc_url` / `api_key` / `domain` / `verify_ssl` — only `policy_name` and `object_prefix` (project-specific operator choices).
- [webapp/app.py](webapp/app.py) `migration_target` POST handler stops capturing those fields from the form. Pre-C1 project files retain their existing fields until the operator re-saves; on re-save the legacy plaintext is stripped (`new_target.pop(...)` for each).
- [webapp/app.py](webapp/app.py) `migration_dedup` and `migration_import` build their cfg dict from `get_user_cfg()` (post-H2: api_key from `g.api_key_obj.decrypted_key`) instead of from `target["api_key"]`.
- [webapp/app.py](webapp/app.py) `migration_dhcp_map` resolves the project's Tenant from `g.api_key_obj.tenant_id` directly (no fuzzy `find_tenant_for_target(target)` lookup needed). Legacy plaintext-target fallback retained for pre-C1 project files.

**Files modified (8):** `webapp/user_manager.py`, `webapp/app.py`, `webapp/engines_manager.py`, `webapp/project_manager.py`, `webapp/templates/migration/target_config.html`. All AST-parse clean.

**Verification grep:** no template renders `target.api_key` or `profile.api_key` anywhere. The remaining `profile["api_key"]` reads in `user_manager.py` and `admin.py` are intentional legacy paths: `_resolve_profile_json` reads from a JSON file on disk; `migrate-json` admin route reads from a JSON file on disk; `is_active_profile_valid` retains the legacy fallback. None are session leaks.

### Security audit Batch A — authorization tightening (2026-05-09)

Resolves audit items C2, C3, C4, M14 from [TODO.md § Security & efficiency audit](TODO.md). All four are authorization-gating fixes that close cross-Domain privilege-escalation paths reachable by any authenticated Domain Admin.

**C2 — Migration routes.** Every migration route (14 in total — `/migration/`, `/migration/new`, `/migration/<id>/parsed|target|dhcp-map|dedup|dedup/update|dhcp/update|rules|rules/update|nat-rules/update|vpn/update|import|delete`) was gated by `@login_required` only — any authenticated Azure user (even a Viewer) could drive a full SMC import. Now `@domain_admin_required` from [webapp/auth_roles.py](webapp/auth_roles.py).

Each project carries a `domain_slug` stamp (added at creation in [webapp/project_manager.py](webapp/project_manager.py)). New helper `_load_migration_project_or_redirect()` in [webapp/app.py](webapp/app.py) enforces that the project's `domain_slug` matches `g.domain.slug` on every load. Legacy projects (no stamp) get stamped with the active Domain on first authenticated read — the constraint becomes enforceable going forward without breaking in-flight migrations. Cross-Domain access attempts are logged + return "Project not found" (don't leak existence). Project list filters to active-Domain-only + legacy.

> **Superseded 2026-05-25.** `_load_migration_project_or_redirect` and the `domain_slug` stamp were unified into `_migration_project_for_domain(project_id, mutating=…)` + `domain_id` on the manifest during the May 25 branch-reconciliation rebase. The C2 cross-Domain refusal invariant was preserved end-to-end (verified via `/verify` against commit `934547c`); only the helper and field names changed. See "Branch reconciliation rebase (2026-05-25)" entry above.

**C3 — Admin Portal infrastructure CRUD.** 18 routes flipped from `@admin_required` (= any Domain Admin) to `@super_admin_required` from [webapp/auth_roles.py](webapp/auth_roles.py):

- 4 × `/admin/tenants*` — Tenant CRUD (cross-Domain infra)
- 5 × `/admin/domains*` — Domain CRUD (cross-Domain infra)
- 5 × `/admin/api-keys*` — API key CRUD (cross-Domain infra)
- `/admin/backup` — downloads encrypted DB + decryption key
- `/admin/migrate-json` — one-time JSON-to-DB import
- `/admin/log-settings` — global log mode/retention (M14)
- `/admin/cache-settings` — global cache TTL (bundled with M14, same shape)

Without this fix, a Domain-A admin could create/delete tenants, API keys, or Domains across the whole platform, including ones they have no Domain Access for. The `/admin/backup` route in particular let any Domain Admin download a ZIP of `flexedge.db` + `encryption.key` — full credential disclosure across all Domains.

The `/admin/users*` routes (5 total) and the dashboard intentionally stay on `@admin_required` per the audit's explicit scope. Follow-up flag: `/admin/users/<id>/edit` lets a Domain Admin assign users to OTHER Domains, which is technically cross-Domain — re-evaluate as part of the next audit pass.

**C4 — Browser SSH terminal cross-Domain check.** Both layers (HTTP launcher in [webapp/engines_manager.py](webapp/engines_manager.py) `node_terminal` + WebSocket handshake in [webapp/engine_terminal.py](webapp/engine_terminal.py) `node_terminal_ws`) only checked `_is_admin(email)` + `last_verify_status == "ok"` — a Domain-A admin could open an SSH terminal on a Domain-B engine simply by guessing/probing `cred_id` URL values. Now both layers refuse (HTTP: redirect with "Credential not found"; WebSocket: close code 4403) when `cred.domain_id != g.domain.id` AND the caller is not Super Admin. Logged at WARN with `email`, `cred_id`, `cred.domain_id`, `active_domain_id` so brute-force attempts are visible.

**M14 — `/admin/log-settings` Super-Admin gate.** Bundled into C3 above. `/admin/cache-settings` flipped along with it (same shape — global infrastructure setting that shouldn't be Domain-Admin-mutable).

**Files modified:** `webapp/app.py`, `webapp/admin.py`, `webapp/engines_manager.py`, `webapp/engine_terminal.py`, `webapp/project_manager.py`. All 5 AST-parse clean.

### Caching Phase 0 — domain-scoped object accessor (2026-05-09)

Eliminates the cross-feature reuse gap: visiting `/engines/clusters` now primes the cache for DHCP credentials, TLS deploy, scan picker, and DHCP scope discovery. Same engine, three+ features, one SMC roundtrip per Domain per TTL.

**New module:** [webapp/domain_objects.py](webapp/domain_objects.py) — single read entry point for SMC objects scoped by Domain. Eight accessors: `engines(domain, cfg)`, `cluster(domain, cfg, name)`, `scopes(domain, cfg, name)`, `policies(domain, cfg)`, `policy(domain, cfg, name)`, `elements(domain, cfg, type, filter, fgt)`, `element(domain, cfg, type, name)`, `dhcp_host(domain, cfg, name)`.

**Storage shape:** cache holds JSON-serialisable dicts (raw SMC API response shape with light extraction). Projection helpers in `domain_objects.py` turn cached dicts back into `EngineSummary` / `ClusterDetail` / `DhcpHostView` instances. SMC version-tolerant (new fields just appear). Redis-swappable later (dicts are JSON-serialisable; dataclasses aren't).

**Section names migrated** to short, object-type-keyed:

| Old | New |
| --- | --- |
| `engines.list` | `engines` |
| `engines.detail` | `cluster` |
| `smc.policy.list` | `policy_list` |
| `smc.policy.<name>` | `policy` (was uncached — Phase 0 wired it; resolves audit H5) |
| `smc.explorer.<type>` | `element_list.<type>` |
| `smc.element.<type>` | `element.<type>` |
| (new) | `scopes` (DHCP scope discovery — resolves caching roadmap item) |
| (new) | `dhcp_host` (single-Host pre-fill in reservation editor) |

**Cross-feature reuse — what now hits the cache that didn't before:**

- `/dhcp/api/.../engines` cascade — was calling `smc_tls_client.list_engines()` live; now reads from `engines` cache.
- `/tls/api/.../engines` cascade — same fix, same section.
- `/engines/api/clusters/<name>/interfaces` (scan picker JSON) — was calling `cluster_detail` live; now reads from `cluster` cache.
- `tools_scan_start` interface lookup — same fix, same section.
- `list_tcp_services_for_picker` / `resolve_port_services` — moved to `domain_objects.elements()`, sharing `element_list.tcp_services` / `element_list.udp_services` with `/browse/<type>`.
- `/dhcp/api/.../engines/<n>/scopes` cascade — newly cached via `scopes` section. The `/dhcp/scopes/discover` POST passes `refresh=True` to warm the cache after a fresh walk.
- `/dhcp/reservations/<id>/edit` — Host pre-fill via new `dhcp_host` section.
- `/policy/<name>` — newly cached, resolves the audit's HIGHEST IMPACT GAP. Queue runner already targeted this section for invalidation; now there's a read wrapper.
- `/api/elements/<type>` and `/api/policy/<name>/rules` — JSON twins now share the same sections as their HTML siblings.
- `/optimize` — shares `policy_list` with `/policies`.

**Queue runner invalidation map updated** ([shared/queue_runner.py:240-300](shared/queue_runner.py#L240)) to use the new short section names. `upload_policy` now also drops `scopes` for the affected engine. Plain element-type pushes drop `element_list.<type>` AND `element.<type>`; if the type is `host`, also drops `dhcp_host`.

**Quick-search section walk** ([webapp/app.py:1042-1086](webapp/app.py#L1042)) updated to recognise the new short names so cached element names still surface in Cmd/Ctrl+K results.

**`cluster_forget`** ([webapp/engines_manager.py](webapp/engines_manager.py)) drops `engines` + `cluster` + `scopes` for the engine — the canonical "I'm done" signal flushes everything keyed to it.

**Files modified:** `webapp/engines_manager.py`, `webapp/dhcp_manager.py`, `webapp/tls_manager.py`, `webapp/app.py`, `shared/queue_runner.py`. **Files added:** `webapp/domain_objects.py`. No schema changes; no DB migrations. All 7 modified files AST-parse clean. Templates' `cache_meta.served_from_cache` / `age_minutes` continue to work — accessors return the same `CachedValue` from `cache_get_or_fetch`.

Doc: [docs/CachingReview.md](docs/CachingReview.md) — updated to reflect Phase 0 landed (was a review/proposal doc; now the canonical reference for the cache architecture).

### Engines → Tools → Scan: MAC harvest fixed — BusyBox `ip` wants `neigh`, not `neighbor` (2026-05-09)

Operator ran our diagnostic block on the engine and reported
**both** `busybox ip neighbor show <ip>` and `busybox ip neighbor
show` (no arg, full table) returned EMPTY output — even though
the kernel ARP cache had a valid REACHABLE entry minutes earlier.

Root cause: BusyBox's stripped `ip` applet uses the SHORT verb
`neigh`, not the iproute2 long form `neighbor`. When BusyBox's
parser hits `neighbor` it silently treats the rest of the line
as garbage and emits no output. The operator's earlier successful
manual run had used the engine's full iproute2 `ip` binary
(without the `busybox` prefix), which accepts both forms — that's
why the entry was visible then but not via our `busybox ip
neighbor` calls.

Fix: change `busybox ip neighbor show` to `busybox ip neigh
show` in:

- [webapp/engine_scan.py](webapp/engine_scan.py) Phase 1 MAC harvest
- [webapp/dhcp_subnet_scan.py](webapp/dhcp_subnet_scan.py) Phase 1 MAC harvest
- [scripts/engine-scan-debug.sh](scripts/engine-scan-debug.sh) Phase 1 (standalone harness)

The previous awk-based filter (added earlier today to defend
against unreliable IP-argument filtering) stays — it's still
needed because BusyBox `ip neigh show <ip>` doesn't reliably
filter on the IP arg either, and we want to prefer REACHABLE
state entries.

Net effect: the result table will now show MAC + vendor for any
host the kernel has ARPed (which is every L2-adjacent host that
just answered ICMP). Confirmed behaviour pattern by the operator's
diagnostic output.

### Engines → Tools → Scan: MAC harvest fixed — BusyBox `ip neighbor show <ip>` filter is unreliable (2026-05-09)

Operator on a /24 attached to the engine's `eth0.2` reported the
scan correctly identified hosts via ICMP but emitted **no MACs**
even though `busybox ip neighbor show 172.16.199.2` on the same
engine cleanly returned:

```text
172.16.199.2 dev eth0.2 lladdr 00:15:5d:c7:32:01 ref 1 used 4/0/0 probes 1 REACHABLE
```

So the kernel cache had the entry — we were just failing to
extract it. Root cause: BusyBox 1.35.0's `ip neighbor show <ip>`
does NOT reliably filter the table by the IP argument. Depending
on the build, it either silently outputs nothing, or ignores the
filter and dumps the full table — at which point our `head -1`
grabs whichever entry happens to be lexically first (typically a
gateway, never our target).

Fix in [webapp/engine_scan.py](webapp/engine_scan.py) Phase 1
(and mirrored in [webapp/dhcp_subnet_scan.py](webapp/dhcp_subnet_scan.py)
+ [scripts/engine-scan-debug.sh](scripts/engine-scan-debug.sh)):
filter the unfiltered output ourselves in awk, matching field 1
against our target IP, and prefer REACHABLE state entries with a
fallback to any state that has an `lladdr`:

```sh
NEIGH=$(busybox ip neighbor show 2>/dev/null | busybox awk -v IP="$ip" '
    $1 == IP && /lladdr/ {
        if (/REACHABLE/) { print; have_reach = 1; exit }
        if (!fallback) fallback = $0
    }
    END { if (!have_reach && fallback) print fallback }
')
```

The MAC regex extraction (and Phase 2's arping-output parsing,
which uses `grep -oE` against the full arping stdout, not the
neighbor table) was already correct — only the kernel-cache
read needed defending.

### Engines → Tools → Scan: dedicated Vendor column + Dead button visibility (2026-05-09)

Two follow-ups to the UX batch:

1. **Vendor column** — operator wanted the OUI lookup as its own
   sortable column rather than inline next to the MAC. Added on
   both [scan_history/detail.html](webapp/templates/scan_history/detail.html)
   (primary) and [tools_scan.html](webapp/templates/engines/tools_scan.html)
   (in-memory fallback). Cell shows the resolved vendor name,
   `unknown` when MAC has no OUI match, `—` when the host has no
   MAC at all. Included in `data-search` so the text filter
   matches vendor names too (typing `cisco` filters to rows from
   Cisco-OUI MACs). Sortable via the standard click-to-sort
   pattern; `data-vendor-sort` carries the lowercased value for
   stable comparisons.

2. **Dead-hosts filter button** was using `btn-outline-dark` with
   a `bg-dark` badge — invisible on the dark Bootstrap theme.
   Switched to `btn-outline-light` (white border + white text
   when inactive, dark text on light fill when active) and the
   badge to `bg-secondary`. Same fix applied to the equivalent
   `Silent` button in the in-memory results render.

### Engines → Tools → Scan: 8-feature UX batch — STOP / Lazy / OUI / sortable / filters / octet-prefix / Back (2026-05-09)

Big UX pass requested by the operator after the per-scan log file
landed. Eight features in this batch, plumbed end-to-end through
[webapp/engine_scan.py](webapp/engine_scan.py) /
[engine_scan_jobs.py](webapp/engine_scan_jobs.py) /
[engines_manager.py](webapp/engines_manager.py) /
[scan_jobs.py](webapp/scan_jobs.py) /
[tools_scan.html](webapp/templates/engines/tools_scan.html) /
[scan_history/detail.html](webapp/templates/scan_history/detail.html).

#### Picker (home screen)

- **OUI vendor database** with download/refresh button — new module
  [webapp/oui_db.py](webapp/oui_db.py) downloads from
  `$FEA_OUI_DB_URL` (defaults to maclookup.app's JSON endpoint per
  operator pick), parses both JSON shapes (with multiple field-name
  variants for forward-compat) and IEEE OUI CSV as fallback, stores
  at `/config/oui.json` (or `$FEA_OUI_DB_PATH`). Status card on the
  picker shows record count + "updated 2d ago" age. Loaded into an
  in-process dict at boot; `oui_vendor(mac)` Jinja global decorates
  every result table's MAC column with the vendor name (e.g.
  `aa:bb:cc:dd:ee:ff · Cisco Systems`).
- **Lazy scan** checkbox — when ticked, Phase 3 sleeps a random
  1-3 seconds between hosts (busybox `sleep $(awk srand+rand)`).
  Slower but gentler on the network and less likely to trip
  rate-limit alarms on target firewalls. EXEC line in the verbose
  log narrates each delay.
- **Octet auto-compile** for Single IP / Range inputs — when the
  selected interface has a /24 (or /16, /8) subnet, the Single IP
  / start / end inputs render with a non-editable prefix span
  (`172.21.20.`) so the operator types only the variable octet
  (`5`). Form-submit JS combines them. If the operator types a
  full IP with dots, it's accepted verbatim — the prefix is only
  prepended when the input is dot-free.

#### During the scan

- **STOP button** in the watcher card. POSTs to
  `/engines/tools/scan/cancel/<scan_id>`; the cancel hook closes
  the paramiko channel mid-stream, the script's readline returns
  EOF, the runner finalises with `state="failed",
  error="cancelled by operator"`. Watcher's poll picks that up and
  redirects to the picker. New API in
  [scan_jobs.py](webapp/scan_jobs.py): `register_cancel_hook` /
  `request_cancel` / `is_cancel_requested` (out-of-band hook
  storage so paramiko channel objects don't leak into the JSON
  status payload).

#### After the scan (scan_history detail)

- **Back to Scan tool** button next to Star/CSV/Delete in the
  header.
- **Filter counter** — `M of N shown` / `M of N match` displayed
  next to the filter input as the operator types or clicks
  category buttons.
- **Big context-aware filter buttons** immediately above the
  table: All / ICMP / ARP only / With open ports / Dead. Each
  carries a live-counted badge. Clicking one filters the table
  to that category. Combines with the text filter (intersect).
- **Sortable column headers** — IP / ICMP / MAC / Hostname / Open
  ports / Closed all click-to-sort. IP uses the numeric-octet
  comparator (so `192.168.1.6` lands before `192.168.1.69` —
  same trick the DHCP leases / engines scan in-memory tables
  already use). Indicators ▲ ▼ next to the active key.

The whole batch is additive — existing scans replay correctly,
new scan_id payload includes the additional `lazy` / `verbose`
flags but ignores them on a re-render. The default port list, the
SMC service-name decoration, the per-scan debug log file, the PTY
mode, and the file-tail watcher dialog from the previous batches
all still work as before.

### Engines → Tools → Scan: watcher tails the debug-log file + 2-decimal progress (2026-05-09)

Operator pointed out that the file-on-disk had everything but
the dialog window only showed the rolling 10-line deque tail
("you are not showing the same in the dialog window"). Now the
watcher's log pane is a true live tail of the same file, fed
through a new endpoint instead of the deque.

**New endpoint**: `GET /engines/tools/scan/log/<scan_id>?offset=N`
([webapp/engines_manager.py](webapp/engines_manager.py)
`tools_scan_log`). Reads the per-scan debug log file from
`offset` to current EOF (capped at 512 KB per call), responds
with `text/plain` body + `X-Log-Offset` header pointing at
the new file position. Path is verified to live under
`scan_log_dir()` before being opened — defense-in-depth even
though the path comes from our own job state.

**Watcher JS** ([webapp/templates/engines/tools_scan.html](webapp/templates/engines/tools_scan.html)):

- Now polls `/scan/status` AND `/scan/log` every 800 ms.
- Tracks `logOffset` across polls; appends only the new bytes
  to the dialog `<pre>`. No more 10-line deque clipping —
  what you see in the dialog matches what's in the file
  byte-for-byte.
- Auto-scrolls to bottom only if the operator was already at
  bottom (so they can scroll up to read older lines without
  the JS yanking them back).
- Caps the in-DOM log at ~1.5 MB; on overflow, drops the
  oldest 20% of content so memory stays bounded on huge scans.
- Pre height bumped 12em → 22em to use the extra log content
  meaningfully.
- One last log fetch fires after the scan transitions to
  `done` / `failed`, so the script footer (`# finished_at`,
  `# counters`, `# host_count`) lands in the dialog before
  the page redirects.

**Progress bar — 2-decimal percentage**. Operator wanted "a
decimal progression in percentage" for valuable feedback. The
existing fraction (`progress / total`) was numeric but didn't
read as progress — now alongside it:

- Bar `width` = `pctNum.toFixed(2) + "%"` — granular for big
  scans where you'd otherwise sit at the same `12%` for 30
  seconds.
- Bar `textContent` = `pctStr + "%"` — visible as a label
  inside the bar itself.
- Counter row shows `1234 / 6605 (18.71%)` instead of just
  `1234 / 6605`.

The deque-based `log_tail` field is still populated server-side
(used by the initial render placeholder + retained for any
future fallback rendering) but is no longer the primary log
source the dialog reads from.

### Engines → Tools → Scan: per-scan debug log file (2026-05-09)

Operator wanted ground-truth verification when the in-page
watcher feels stuck or rolls over too fast — "i want a verbose
logging somewhere that i can verify". Now every scan writes
EVERY raw line received from the engine over SSH to a per-scan
file the operator can `tail -f` from a separate shell.

**Path discovery** ([webapp/engine_scan.py](webapp/engine_scan.py)
`scan_log_dir()` / `scan_log_path()`): tries
`$FEA_SCAN_LOG_DIR` first, then `/config/logs` (the standard
mounted volume in Docker deployments), falls back to
`/tmp/flexedge-scan-logs`. Directory is auto-created.

**Path surfaced three ways**:

1. **Watcher card** in
   [webapp/templates/engines/tools_scan.html](webapp/templates/engines/tools_scan.html)
   — small grey footer below the dark log block:

   > Full debug log (every line received over SSH, including
   > stderr) is being written to
   > `/config/logs/engine-scan-abc123.log` — `tail -f` from a
   > separate shell to verify progress when the watcher above
   > feels stuck.

2. **Python `log.info`** at scan start
   ([webapp/engine_scan_jobs.py](webapp/engine_scan_jobs.py)):
   `engine_scan_jobs: scan_id=abc123 debug_log=/config/logs/engine-scan-abc123.log`
   — visible in the gunicorn / `make dev` console output.

3. **`/scan/status` JSON** carries `debug_log_path` as an extra,
   so the watcher's poll keeps the path even if the page reloads.

**File contents** — written line-buffered so `tail -f` is
responsive:

```log
# FlexEdgeAdmin engine-scan debug log
# started_at  : 2026-05-09T08:42:13+00:00
# target      : 172.21.20.99:22
# ip_list_size: 254
# ports_count : 25
# verbose     : True
# command     : sh -c '...' _ 32 1 1 2 2 20,21,22,... 1 172.21.20.1 ...
# ──────────────────────────────────────────────
EXEC === Phase 1 (ICMP) starting: 254 targets ===
EXEC busybox ping -c 1 -W 1 -q 172.21.20.1
172.21.20.1 ICMP_OK
… every line verbatim …
# ──────────────────────────────────────────────
# finished_at: 2026-05-09T08:48:51+00:00
# error      : (none)
# counters   : {'icmp_replies': 50, 'arp_replies': 2, ...}
# host_count : 52
```

The file captures **everything** the parser sees, before any
tag-based routing — including stderr leaking through the PTY
(missing applets, shell syntax errors), unknown lines, and the
phase-boundary markers in their raw `EXEC === Phase X ===`
form. So when the watcher's 10-line deque saturates and the
operator can't tell which phase is running, the file has the
full ground truth.

Plumbed through:
[`engine_scan._run_scan`](webapp/engine_scan.py)`(...,
debug_log_path=...)` → file open with `buffering=1` (line-buffered)
→ each `for raw in iter(stdout.readline, '')` writes raw line
to disk before parsing → `finally` closes with footer summary
even on exceptions. Best-effort: file open failure logs a
warning and the scan runs anyway without the file.

### Engines → Tools → Scan: phase-boundary markers + PTY mode for live visibility (2026-05-08)

After the `$@`-clobber fix landed, operator reported the watcher
showed only Phase 1 lines mid-scan ("the debug scan log is not
showing up… only the following comes: $ busybox ping … / 172.x
ICMP reply"). Two reinforcing causes:

1. **Watcher's log_tail is a 10-line deque.** On a /24 scan, Phase 1
   alone emits ~500 events; mid-Phase-1 the deque holds early
   pings only and the operator sees no clear "what phase am I
   on?" signal. Phase 3 takes minutes (6,350 probes / 32
   parallel × 2s timeout = ~6 minutes wall-clock) before its
   output starts replacing Phase 1 in the deque.

2. **No PTY = full-buffered remote stdout.** Without
   `get_pty=True`, each parallel subshell's stdout is a pipe
   (full-buffered by libc, ~4 KB chunks). Subshells emit only
   1-2 lines before exiting; output sits in the buffer until
   subshell exit, making early-Phase-1 output appear bursty
   and Phase 3 output appear chunky.

**Fix 1 — phase-boundary markers** added to
[webapp/engine_scan.py](webapp/engine_scan.py) `_SCAN_SCRIPT`.
Always emitted (not gated by VERBOSE) — the watcher renders
each as `$ === Phase X … ===` in the live log:

```log
=== Phase 1 (ICMP) starting: 254 targets ===
=== Phase 1 done: 50 OK / 204 FAIL ===
=== Phase 2 (arping fallback) starting ===
=== Phase 3 (TCP port probe) starting: 254 targets x 25 ports ===
=== Phase 3 done ===
=== Phase 4 (RDNS) starting: 50 reachable hosts ===
=== Phase 4 done ===
=== Scan script finished ===
```

8 lines for the entire scan, so they survive the 10-line
deque rollover and operators always see the current phase.

**Fix 2 — PTY mode** for the SSH `exec_command`:

```python
_, stdout, stderr = client.exec_command(
    cmd, timeout=exec_timeout_s, get_pty=True)
```

Allocates a pseudo-tty on the remote side, which:

- Switches stdout from full-buffered (pipe) to line-buffered
  (tty) — output flushes per line, not per ~4 KB chunk.
- Implicitly merges stderr into stdout, so future script-level
  errors (bad shell construct, busybox applet missing) become
  visible in the watcher log instead of being swallowed until
  the channel closes.

Together these two changes mean the watcher log now reads as a
clear narrative on every scan ("Phase 1 starting → Phase 1
done → Phase 2 starting → Phase 3 starting → some `$ busybox
nc` lines → Phase 3 done → complete: ICMP=N ARP=N open=N"),
even on big subnets where the deque otherwise stays
saturated with Phase 1 events for many seconds.

### Engines → Tools → Scan: CRITICAL FIX — Phase 2 was clobbering the target list (2026-05-08)

**Root cause of the "scan finds nothing" symptom.** Operator ran
the standalone debug harness (`scripts/engine-scan-debug.sh`) and
pasted the output. The smoking gun:

```text
→ 172.21.20.15:80  OPEN              ← real, port 80 actually open
→ ICMP_OK:80  closed-refused  (nc: bad address 'ICMP_OK')
                ^^^^^^^^^^^ that is not an IP
```

Phase 2's `set -- $line; ip=$1; state=$2` was **mutating the
top-level `"$@"`** — the script's original target list — every
iteration. After the read loop finished, `"$@"` was no longer
`("172.21.20.10", "172.21.20.11", …)` but `("<last_ip>",
"<last_state>")`. Phase 3 then did `for ip in "$@"` and dutifully
attempted nc probes against a host literally named `"ICMP_FAIL"`
(or `"ICMP_OK"`), getting `nc: bad address` for every "port".

Real-world impact: the operator's scans of full /24s with many
ICMP-failing hosts were probing **< 1% of intended targets** —
last-failed IP plus the literal string `"ICMP_FAIL"` — which
explains why the firewall logs showed barely any TCP SYN. The
script was working for a single OK host (lab test) because
Phase 2 still ran with `set -- "$ip ICMP_OK"`, so `"$@"` ended
up `("$ip", "ICMP_OK")` — giving real probes for the host plus
bogus ones for `ICMP_OK`. Functionality looked half-broken; the
"closed-refused (nc: bad address)" lines in the harness output
made the corruption visible.

Fix in [webapp/engine_scan.py](webapp/engine_scan.py)
`_SCAN_SCRIPT` Phase 2 (and mirrored in
[scripts/engine-scan-debug.sh](scripts/engine-scan-debug.sh)):

```sh
# Was:
while IFS= read -r line; do
    set -- $line                # ← clobbers "$@" — DON'T
    ip=$1; state=$2
    ...

# Now:
while read -r ip state; do      # ← reads directly into named vars
    ...
```

`read -r ip state` with default IFS splits each line into the two
named variables without touching positional parameters. Phase 3
now sees the full original target list intact.

[webapp/dhcp_subnet_scan.py](webapp/dhcp_subnet_scan.py) has the
same `set --` pattern but no Phase 3 that consumes `"$@"` after
the loop, so the bug was harmless there — left untouched in this
fix to keep the changeset tight (worth cleaning up later for
consistency).

### Engines → Tools → Scan: verbose-log toggle for live troubleshooting (2026-05-08)

When a scan looks empty (the "I see only ICMP, no SYN" symptom
that uncovered the BusyBox issues earlier today), operators
need to confirm which commands are actually firing on the
engine. New picker checkbox surfaces that:

> ☐ Verbose log — show every `busybox ping / arping / nc /
> nslookup` command in the live watcher (slower; useful for
> troubleshooting why a scan looks empty).

When ticked, the [scan script](webapp/engine_scan.py) emits
one extra `EXEC <command>` line BEFORE each network command
runs. Per Phase:

- Phase 1: `EXEC busybox ping -c 1 -W 1 -q 172.21.20.10`
- Phase 2: `EXEC busybox arping -c 1 -w 1 -I eth0 172.21.20.10`
- Phase 3: `EXEC busybox timeout 2 busybox nc 172.21.20.10 443`
- Phase 4: `EXEC busybox nslookup 172.21.20.10`

The Python parser
([webapp/engine_scan.py](webapp/engine_scan.py) `_run_scan`)
recognizes the `EXEC` tag at the front of the line and routes
it to a new `{tag: "EXEC", command: "…"}` event. The job
runner
([webapp/engine_scan_jobs.py](webapp/engine_scan_jobs.py)
`_on_event`) appends each as `$ <command>` into the
`log_tail` deque the watcher already polls. Operators see
the most recent ~10 commands streaming live in the dark
console block at the bottom of the watcher card.

Off by default — verbose mode multiplies stdout volume by
2-3× for big scans (one extra line per command per
ip-port). Stays clean for normal use, flips on cleanly when
something looks broken.

The verbose flag is per-scan (form POST), not a stored
setting. Plumbed end-to-end:
[tools_scan.html](webapp/templates/engines/tools_scan.html)
checkbox → `tools_scan_start` route reads
`request.form.get("verbose") == "1"` → `start_scan(...,
verbose=verbose)` → `_run_scan(..., verbose=verbose)` →
`$VERBOSE=1` shell script arg. The audit row
(`engines.scan_started`) records `verbose=1|0` for traceability.

### Engines → Tools → Scan: service-friendly chip picker + coherent result chips (2026-05-08)

The TCP-ports input in the scan picker was a plain comma-list text
field — operators had to remember which port number is which
service. The result table already shows `443 · HTTPS` style names
(landed earlier today via TODO #2), so the picker felt
inconsistent.

**Picker now uses chips + autocomplete** in
[webapp/templates/engines/tools_scan.html](webapp/templates/engines/tools_scan.html):

- The 25 default ports render as chips on first paint, each
  showing `443 · HTTPS` / `22 · SSH` / `3389 · RDP` (matched from
  the operator's own SMC `tcp_services` list — same cache the
  result table reads from).
- Each chip has an `×` button to remove that port from the scan.
- A typeahead input below — type `rdp` to find SMC service
  RDP, type `8443` to add a raw port, type `8000-8010` to add a
  range. Up to 12 suggestions shown (services first by name
  match, with raw-port/range as the top suggestion when the
  query parses as numeric).
- Reset link → repopulate with the default 25 chips. Clear
  link → drop all chips. The "Skip port scan" checkbox now
  auto-derives from the chip count: empty chips = scan skipped,
  any chips = scan runs.
- A live counter ("· 25 ports selected" / "· no ports — port
  scan will be skipped") next to the form-text help line.

**Source-of-truth state** is a `Set<int>` of selected port
numbers in the JS module. A hidden `<input name="ports">` is
kept in sync as comma-separated so the existing server-side
parser (`parse_port_list`) needs no changes. Form posts
behave exactly as before.

**Picker payload** — the route handler builds two structures
on the picker render (cached via the same
`smc.explorer.tcp_services` section as the chip-name resolver):

- `picker_port_services_map`: `{port: name}` for the chip
  labels.
- `tcp_services_for_picker`: `[{name, port_low, port_high,
  label, search}]` for autocomplete suggestions. UDP services
  intentionally excluded — the scan tool is TCP-only in v1.
  Catch-all ranges (>256 ports) skipped to keep "TCP All" out
  of the suggestion list.

**Result-table chips polished** for coherence with the picker:

- Open-port chips use `bg-info text-dark` when the port has an
  SMC name match, `bg-secondary` (gray) when it doesn't —
  visually identical to the picker chips so operators can
  follow the same `443 · HTTPS` pattern from "what to scan" to
  "what came back".
- The `Closed` column previously printed every closed port
  number as a comma-separated string (typically 20+ entries
  per host, dominating row height). Collapsed to a single `N
  closed` count with the full list in a `title=` tooltip on
  hover. Same treatment in
  [webapp/templates/scan_history/detail.html](webapp/templates/scan_history/detail.html)
  (the primary results view) and
  [webapp/templates/engines/tools_scan.html](webapp/templates/engines/tools_scan.html)
  (in-memory fallback).

Helpers added in
[webapp/engines_manager.py](webapp/engines_manager.py):

- `list_tcp_services_for_picker(domain_id, cfg)` — picker-ready
  TCP service list. Reuses the SMC Explorer cache section so
  one fetch serves both the chip-name resolver
  (`resolve_port_services`) and the typeahead list. Empty
  list on any failure → picker degrades gracefully to
  typing-only port input.

### Engines → Tools → Scan: Phase 3 probe form rewritten — BusyBox `nc` lacks `-z` (2026-05-08)

Even after the `busybox <applet>` prefix fix landed, the operator
ran `busybox nc -h` on the engine and reported the actual flag
list:

```text
Usage: nc [-iN] [-wN] [-l] [-p PORT] [-f FILE|IPADDR PORT] [-e PROG]
```

No `-z`. The Forcepoint engine's BusyBox `nc` build is stripped
of zero-I/O scan mode entirely. `busybox nc -z -w 1 host port`
was being parsed as "unknown option `-z`", failing fast, and
recording every port as `closed` — same downstream symptom as
before, just one layer up.

Fix in [webapp/engine_scan.py](webapp/engine_scan.py) Phase 3:

```sh
busybox timeout "$CT" busybox nc "$ip" "$port" < /dev/null > /dev/null 2>&1
```

We open a real connection (no `-z`), immediately send EOF from
`/dev/null` so our write side closes, and let the remote close.
`busybox timeout` wraps the call to bound wall-clock time on
blackholed targets where the kernel's TCP RTO would otherwise
stretch past `$CT` seconds. Exit-code mapping the parser uses:

| Exit | Meaning | Reported as |
| ---- | ------- | ----------- |
| `0` | Connect succeeded and remote closed within `$CT` seconds | `open` |
| `1` | Connection refused fast (RST received) | `closed` |
| `124` | Timeout fired (blackholed firewall OR remote refused to close) | `closed` |

Default `port_timeout_s` bumped from `1` → `2` (in both
[webapp/engine_scan.py](webapp/engine_scan.py) and
[webapp/engine_scan_jobs.py](webapp/engine_scan_jobs.py)) to give
slow-closing services more time before the timeout misclassifies
them as closed. Operator's lab test confirmed `timeout 2` reliably
distinguishes open vs closed against a sshd target on the engine.

**Known false-negative**: chatty long-lived services that accept a
connection and then sit there waiting for a request without
honoring our half-close (some custom apps, RDP) get killed by
`timeout` and reported `closed`. Acceptable for v1 — if it becomes
a problem, a Python-side paramiko TCP probe (controlled close, no
shell timing) would replace this entirely.

`arping` flag set fully matches what the script uses (`-c`, `-w`,
`-I`) — no change needed there.

### SSH-issued shell scripts: `busybox <applet>` invocation everywhere (2026-05-08)

Operator confirmed via the engine's `busybox --help` output that the
Forcepoint NGFW BusyBox build on their cluster does NOT populate
applet symlinks under /bin for every applet. The applet listing —
which includes `nc`, `arping`, `nslookup`, `awk`, `ip`, `head`,
`grep`, `sed`, `mktemp`, `rm`, `tr`, `killall` — comes with the
note that "[applets] are usable only using the busybox command".
Bare `nc -z` / `arping` / `nslookup` invocations were silently
returning "command not found" exit codes, which is why the scan
tool's Phase 3 reported every port as `closed` and the firewall
saw zero TCP SYN egress.

Audit and fix landed across three files:

1. **[webapp/engine_scan.py](webapp/engine_scan.py)** `_SCAN_SCRIPT`
   — every applet (`ping`, `ip neighbor`, `head`, `grep`, `arping`,
   `ip route`, `awk`, `nc`, `tr`, `nslookup`, `sed`, `mktemp`,
   `rm`) now prefixed with `busybox`. Shell builtins (`printf`,
   `[`, `read`, `set`, `wait`, `for`, `:`) left bare.
2. **[webapp/dhcp_subnet_scan.py](webapp/dhcp_subnet_scan.py)**
   `_SCAN_SCRIPT` — same fix for its 2-phase ICMP+arping scan
   (Phase 2 was hitting the same silent-skip on engines without
   the symlinks).
3. **[webapp/dhcp_pusher.py](webapp/dhcp_pusher.py)**
   `_reload_dhcpd` — replaced `pkill -HUP -x <name>` with
   `busybox killall -HUP <name>`. `pkill` is **not in the
   BusyBox applet table at all** on the engine; only `kill` and
   `killall` are. BusyBox `killall` matches process basename
   exactly by default, which is the same semantics `pkill -x`
   provides — so behavior is preserved on engines that worked
   before AND fixed on engines where the legacy command was
   silently failing.

`busybox <applet>` is universally safe — it works on every
BusyBox build because `busybox` itself is always on PATH, and
`busybox <applet>` is the canonical multi-call invocation. On
engines that DO populate symlinks (so bare `nc` would also
work), going through `busybox` adds one syscall per command
and is otherwise a no-op.

Standing rule (saved to memory `feedback_busybox_applet_prefix`):
every shell script we ship over SSH from FlexEdge to a Forcepoint
NGFW must invoke external utilities as `busybox <applet>`, never
bare. Shell builtins handled directly by ash do not need the
prefix. When adding a new SSH-issued command, double-check the
applet name against the engine's `busybox --list` (the operator's
list is the canonical reference); commands not in that list need
a different applet entirely (e.g. `pkill` → `killall`).

Files NOT touched: [webapp/dhcp_ssh.py](webapp/dhcp_ssh.py)
(only issues `echo flexedge-ok` / `echo flexedge-first-contact`
— `echo` is a shell builtin), [webapp/engine_terminal.py](webapp/engine_terminal.py)
(interactive PTY, the operator types their own commands).

### Engines → Tools → Scan: port → service-name labels in result table (2026-05-08)

Open-port badges in the scan-result table now show the SMC service
name next to the port number — `443 (HTTPS)`, `3389 (RDP)`,
`8080 (Custom-HTTP-Alt)` — pulled from the operator's own SMC
`tcp_services` / `udp_services` element lists. Names matter to
operators because they reflect what they've defined in SMC, not a
generic IANA list. Custom services (e.g. an internal app on a
non-standard port) flow through automatically.

The lookup goes through the existing `smc.explorer.tcp_services` /
`smc.explorer.udp_services` cache sections (Quick refresh, key
`(domain_id, "", "")`) — same cache the SMC Explorer already
populates, so the lookup is free if the operator has visited
`/browse/tcp_services` in the last hour. Auto-invalidated by the
queue runner after any service-element write.

Two-pass merge so specific names beat catch-alls: range services
applied first, single-port services overwrite second. Ranges wider
than 256 ports are skipped entirely (those are usually "TCP All" /
all-ports categories that would clobber every well-known port name
and reduce signal). On any cache or SMC failure the lookup returns
an empty dict — the table falls back to bare port numbers, scan
results still render.

The hosts filter on the scan detail page now matches against the
service name too — typing `rdp` filters to rows with port 3389
open, `https` to rows with 443 open, etc. Placeholder updated:
`filter by IP / hostname / MAC / port / service…`.

Helper: `webapp.engines_manager.resolve_port_services(domain_id,
cfg)` — public so [scan_history.routes.detail](webapp/scan_history/routes.py)
(the primary results view operators land on) and the in-memory
fallback render in `tools_scan` both use it.

### Engines → Tools → Scan: Phase 3 port scan now covers ALL targets (2026-05-08)

Operator reported only seeing ICMP traffic from the firewall, no
`nc -z` TCP probes, when scanning a remote subnet. Root cause:
[webapp/engine_scan.py](webapp/engine_scan.py) Phase 3 was gated by
`[ -s "$REACHABLE" ]` — the script only port-scanned hosts that had
replied to ICMP (Phase 1) or arping (Phase 2). When the engine
scanned across a routed boundary, ICMP-dropping hosts (Windows
desktops, web servers behind host firewalls) never made it into
REACHABLE, Phase 3 silently skipped, and the only traffic that ever
left the engine was the Phase 1 ICMP echo requests. Exactly what the
operator observed.

Fix: Phase 3 now iterates over the full target list (`for ip in
"$@"`), regardless of L1/L2 reply. Phase 4 (RDNS) keeps its
REACHABLE gate because reverse-DNS on dead IPs is just noise. As a
side benefit, the progress bar's `total` math
(`len(ip_list) + len(ip_list)*len(ports)`) now matches the actual
event count exactly — before the fix, progress only reached 100%
when every host replied to ICMP.

Worst-case wall time on a fully-silent /24 × 25 ports = 6,375 nc
probes. With `batch=32` parallelism and `port_timeout_s=1`, that's
~200 seconds — well within the 900s exec_timeout. The existing
8000-op soft warn / 16384-op hard cap already gate larger fan-outs.

Doc update: [docs/Engines-ScanTool.md](docs/Engines-ScanTool.md)
phase listing rewritten + a paragraph on the design intent ("Phase 3
deliberately ignores L1/L2 reachability — that's the point of
running Tools→Scan against a remote subnet").

### Session summary — 2026-05-08

Big day. Landed in this session, in roughly this order:

1. Bug: `InvalidRequestError: Instance ... is not persistent within this Session` on `/dhcp/credentials/rule/install` and siblings — bypass-queue cleanup detached `change` before the route refreshed it.
2. Bug: `/dhcp/scopes/<id>/leases` cross-Domain diagnostic — empty-state alert now lists OTHER Domains (operator-accessible) that have credentials for the engine, with one-click "Switch to X" buttons.
3. Feature: **sgInfo on-demand collection** — per-node "Collect" button on the cluster_detail page, background daemon-thread, in-browser archive viewer with file tree + text reader + raw `.gz` download, history list. Works for node-initiated-contact engines because the SMC management channel is bidirectional once established.
4. UX: engine name in `/dhcp/credentials` Card 3 is now a link to `/engines/clusters/<engine>`.
5. Standing rule: **TODO-item-1 credential-gated visibility** — `/dhcp/scopes` + scope ops + Tools/Scan picker hide engines without fully-verified SSH credentials. `?show_all=1` escape hatch for cleanup. sgInfo intentionally exempt.
6. Bug: **stale-form detector** for 11 `/dhcp/credentials/*` + `/dhcp/scopes/discover` routes — refuses with clear "page is out of sync, reload" instead of cryptic "no enrollment record" downstream.
7. Bug: `BuildError: dhcp.credentials` → fixed to `dhcp.credentials_list` at 6 call sites (4 added today, 2 pre-existing).
8. **Caching rollout phase 1**: `engines.detail` cached, `engines.list` shared with Tools/Scan, family-wide refresh, `cluster_forget` invalidation extended.
9. **Caching rollout phase 2**: `smc.explorer.<type>`, `smc.element.<type>`, `smc.policy.list` cached. Queue runner invalidation map aligned with the single-section + multi-key shape.
10. **Cache TTL tiers reified**: `LOOSE_REFRESH_TTL` (24 h) and `QUICK_REFRESH_TTL` (1 h) with operator overrides via `/admin/cache-settings`. All call sites switched off raw seconds. Going forward, talk about Loose/Quick by name.

End-of-session state: roadmap pinned at the top of [TODO.md](TODO.md) — TCP scan bug → TCP scan service-name UX → Policies dedupe + NAT → Caching phase 3 → TLS Let's Encrypt CRUD design round.

### Cache TTL levels: Loose / Quick + admin settings page (2026-05-08)

Reified the TTL rule established during the phase 1+2 rollout into
two named tiers operators talk about by name, not by raw seconds:

- **Loose refresh** — `LOOSE_REFRESH_TTL` = 24 h. For inventory data
  FlexEdge doesn't write to (engine list, cluster detail, policy
  list, TLS engine settings, scope discovery).
- **Quick refresh** — `QUICK_REFRESH_TTL` = 1 h. For data FlexEdge
  writes via the queue (host/network/service elements, policy rules,
  reservation Hosts).

Constants + getters (`get_loose_ttl()`, `get_quick_ttl()`) live in
[shared/smc_cache.py](shared/smc_cache.py). Both tiers are operator-
overridable through `platform_settings` keys
`cache_ttl_loose_seconds` / `cache_ttl_quick_seconds`. The getters
memoise the override per process; `reload_ttl_settings()` clears the
memo after a save so the next read picks up the new value without a
restart.

All existing call sites switched from raw `ttl=86400` / `ttl=3600`
literals to the named getters: `clusters`, `cluster_detail`,
`tools_scan` GET (Loose); `browse`, `detail` (Quick); `policies`
(Loose). Going forward, every new cache call site picks one of the
two — no more raw seconds.

**Admin UI**: `/admin/cache-settings` ([webapp/admin.py:cache_settings](webapp/admin.py))
with editable hour fields for both tiers, a Reset-to-defaults button,
and a live cache snapshot (hits / misses / hit-ratio / per-section
entry counts via `smc_cache.stats()`). Sidebar entry under Admin.
Hard cap: 24 h per tier. Floor: 1 minute. Documented caveat — TTL
changes only affect newly-CREATED sections, since `_get_section_cache`
sets TTL at section creation; restart for full effect on long-lived
sections.

### Caching rollout phase 2: SMC Explorer + policies list (2026-05-08)

TODO-item-2 phase 2 — biggest user-visible cache win across the SMC
Explorer pages. Standing rules from phase 1 carry over (TTL rule B,
per-page Refresh button, family-wide refresh).

- **`smc.explorer.<type_key>` section** — `/browse/<type>` for hosts,
  networks, address ranges, FQDNs, services, groups, etc. ([webapp/app.py:browse](webapp/app.py)).
  Cache key `(domain_id, filter_text, fgt_only)` so different filter
  states cache independently. TTL 1 h (FlexEdge writes via the queue,
  per Q1.B). Refresh button + freshness footer on
  [webapp/templates/browse.html](webapp/templates/browse.html).
- **`smc.element.<type_key>` section** — `/detail/<type>/<name>`
  per-element view ([webapp/app.py:detail](webapp/app.py)). Cache key
  `(domain_id, element_name)`. TTL 1 h. Refresh button on
  [webapp/templates/detail.html](webapp/templates/detail.html).
- **`smc.policy.list` section** — `/policies` index ([webapp/app.py:policies](webapp/app.py)).
  Cache key `(domain_id,)`. TTL 24 h (FlexEdge doesn't create or
  delete policies — the rule list within a policy IS writeable, but
  that's a different cache section that lands in phase 3). Refresh
  button on [webapp/templates/policies.html](webapp/templates/policies.html).
- **Family-wide refresh** — `?refresh=1` on `/browse/<type>` also
  invalidates the entire `smc.element.<type>` section so deeper
  visits land on fresh data without a second click.

Aligned the queue runner's invalidation map ([shared/queue_runner.py](shared/queue_runner.py))
to match phase 1 + phase 2 cache shapes:

- `upload_policy` push: drops `engines.list` (whole section), the
  specific `engines.detail` entry by `(domain_id, engine_name)`, and
  the specific `smc.policy` entry by `(domain_id, policy_name)`.
  Previously it targeted bogus per-engine / per-policy section names
  that never existed in the cache, so phase 1's `engines.detail` cache
  wouldn't have been auto-invalidated after deploys.
- Plain element create/update/delete (`host`, `network`, `service`,
  `group`, etc.): drops both `smc.explorer.<type>` AND
  `smc.element.<type>`, so a freshly-created host shows up in both
  the list view and any cached element-detail page.

Phase 2 nets ~4 SMC round-trips saved per typical operator session
across the Explorer + Policies pages, plus eliminates the
"phase 1 cache survives 24 h despite a recent deploy" symptom that
the old (mis-targeted) invalidation map would have produced.

### Caching rollout phase 1: engines.detail + tools_scan inventory share (2026-05-08)

TODO-item-2 phase 1 — first slice of the engine-objects caching plan.
Operator-confirmed picks (TODO.md Round 2): TTL rule = "by FlexEdge
write-or-not" (B); Refresh button placement = per-page; Refresh
scope = family-wide.

- **`engines.detail` section** — `/engines/clusters/<engine>` now goes
  through `cache_get_or_fetch` ([webapp/engines_manager.py:cluster_detail](webapp/engines_manager.py)).
  Cache key `(domain_id, engine_name)`, TTL 24 h (read-only inventory
  per Q1.B). Refresh button + freshness footer added to
  [webapp/templates/engines/cluster_detail.html](webapp/templates/engines/cluster_detail.html).
- **`engines.list` shared by Tools/Scan** — the GET handler at
  `/engines/tools/scan` previously opened its own SMC session and
  re-fetched the cluster list. Now reads from the same `engines.list`
  cache as `/engines/clusters` (key `(domain_id,)`, TTL 24 h). Refresh
  button added to the Tools/Scan picker. Eliminates a redundant SMC
  fetch when the operator navigates Clusters → Tools/Scan.
- **Family-wide refresh** — `engines.list?refresh=1` (from either
  Clusters or Tools/Scan) now also invalidates the entire
  `engines.detail` section. Operator's mental model is "give me
  current data on the whole engines feature" — no surprise stale
  per-engine page after a top-level refresh.
- **Forget extended** — `cluster_forget` now drops both `engines.list`
  AND the engine's `engines.detail` entry, since Forget is the
  "I'm done with this engine" signal.

Scoping note: the TLS deploy form's "engine cascade" calls a
different function (`smc_tls_client.list_engines` — multi-stage
discovery, dict shape) than `engine_inquiry.list_clusters`. It will
get its own `tls.engines` section in the TLS rollout step (step 6
in TODO.md), not consolidated with `engines.list`.

Remaining caching work (separate commits): `smc.explorer.<type>`,
`smc.policy.<name>`, `dhcp.scopes.<engine>`, `dhcp.host.<name>`,
TLS sections; plus background warming on login (Q6) and drift-
detector → cache invalidation hook (Q11).

### Fix: BuildError on Tools/Scan + 5 other broken `dhcp.credentials` refs (2026-05-08)

The credentials route is `dhcp.credentials_list`, not `dhcp.credentials`.
Six call sites used the wrong endpoint name and would raise
`werkzeug.routing.BuildError` whenever the `url_for` evaluated:

- `webapp/templates/engines/tools_scan.html` — two banners I added today
  for credential-gating; pages crashed when the inventory was filtered
  to zero or any clusters were hidden.
- `webapp/templates/dhcp/scopes.html` — two banners I added today for
  the same reason.
- `webapp/engines_manager.py` — pre-existing breakage in
  `/engines/credentials` redirect (line 383) and the terminal route's
  unverified-credential redirect (line 943). Both unreachable from
  the happy path so they hadn't surfaced before.

All six fixed to `dhcp.credentials_list`.

### Stale-form detection for DHCP + Credentials POSTs (2026-05-08)

TODO-item-3 — fixes the cryptic "Refresh failed: no enrollment record
for engine 'X' on domain 'Y'" error users hit after switching the
topbar Domain selector.

**Root cause.** Many `/dhcp/credentials/*` and `/dhcp/scopes/discover`
routes still POST a legacy `tenant_id` (and sometimes `api_key_id`)
hidden field that's baked into the page HTML at render time. After
the operator switches Domain in the topbar, any AJAX form still in
the DOM (wizard buttons, refresh-state, modals) submits with the OLD
context. The pre-Multi-Domain-Revamp resolution path
(`Domain.query.join(ApiKey).filter(ApiKey.tenant_id == form_tid)`)
sometimes coincidentally resolved to the *new* session Domain,
producing the unhelpful "no enrollment record for X on Y" downstream
when the engine actually only existed in the OLD Domain's data.

**Fix.** New helper `_check_stale_form_or_response()` in
[webapp/dhcp_manager.py](webapp/dhcp_manager.py) compares the form's
`tenant_id` / `api_key_id` against `g.domain.id`,
`g.domain.api_key.tenant_id`, and `g.domain.api_key.id`
(authoritative). On mismatch, refuses with a clear message —
HTTP 409 + JSON for AJAX (`code: stale_form`), flash + redirect for
form POSTs:

> This page was loaded for a different Domain than the one currently
> active in the topbar. Reload the page and try again — the form
> data references stale context.

Applied at the entry of every form-tenant_id route (11 sites): scope
discover; credentials refresh / discover-nodes / rule install /
policy install / rule remove; drift recovery overwrite / add; per-node
bootstrap / force-reset / bulk-bootstrap. Form fields stay (existing
downstream code reads them); the helper is a guard that fires before
domain mis-resolution can happen.

The detection is permissive on the form value's *name* — templates
sometimes send `tenant_id` carrying a real `Tenant.id`, sometimes
carrying a `Domain.id` (the credentials.html template historically
conflated `tid` with `c.domain_id`). Both interpretations are
accepted as valid when they match the active session; only when
*neither* matches do we flag stale.

Operator-visible improvement: instead of being told an engine doesn't
exist when it visibly does on screen, they now get a clear "your page
is out of sync, reload" message that points at the actual cause.

### Credential-gated visibility across DHCP and Tools/Scan (2026-05-08)

TODO-item-1 — operator-facing pages now hide engines/scopes that have
no fully-verified SSH credentials in the active Domain. Hard-filter
style (entries are removed, not greyed-out); admins can reveal them
for cleanup via `?show_all=1`.

**Validity rule** (in `webapp/engine_credentials.py`):

- New helpers `is_engine_credentials_valid(domain_id, engine_name)`
  and `valid_engines_for_domain(domain_id)`.
- "Valid" = at least one credential row exists AND every credential
  row for the engine has `last_verify_status='ok'`. Partial enrolment
  (cluster has 2 nodes but only 1 enrolled) can't be detected from
  the DB alone — accepted trade-off, the bulk-enroll workflow always
  covers every node.

**Where the gate fires:**

| Surface | Behaviour |
| --- | --- |
| `/dhcp/scopes` | Filters out scopes whose engine isn't valid; shows a `+N hidden` info banner with **Show all** escape hatch (`?show_all=1`) for cleanup. Empty state explains the situation when every scope is hidden. |
| `/dhcp/scopes/<id>` and every operation behind it (leases viewer, subnet scan, Phase-4 deploy/preview/resync, reservation new/edit/bulk-delete, leases-→-reservation promote) | Redirect to `/dhcp/scopes` with a flash. New helper `_scope_with_creds_or_redirect()`; pure-FlexEdge ops (`enable` / `disable` / `delete` / `sync`) keep the lenient `_scope_or_404()` so admins can still clean up stale rows. |
| `/engines/tools/scan` GET | Cluster inventory filtered to valid engines. Banner reports the hidden count and points at `/dhcp/credentials`. Empty-state copy when zero engines pass. |
| `/engines/tools/scan` POST | Server-side gate refuses if `engine_name` isn't valid. Defence in depth — a direct curl can't bypass the GET filter. |
| Terminal | Already correctly per-node gated (template button disabled, HTTP route guard, WebSocket handshake). No change. |
| sgInfo collection (cluster_detail "Collect" button) | **Exempt.** Rides the SMC management channel, doesn't need SSH. |

### UI: top-center search bar, pinned bookmarks, evident sidebar sections (2026-05-08)

Three quality-of-life improvements landing together in
[webapp/templates/base.html](webapp/templates/base.html):

- **Sidebar section labels are now obvious.** Bumped from `0.7rem
  #6b7280` (gray-on-gray, lost against the sidebar bg) to
  `0.78rem #d1d5db` **bold**, with a top border separating each
  section + extra top padding. The `.nav-link` font shrank to
  `0.86rem` so the section header visually dominates its items.
  First-section border is masked so the sidebar doesn't open with a
  stray line. Operators stop hunting for which section a feature
  belongs to.
- **Top-center quick search** with `Cmd/Ctrl+K` to focus from
  anywhere. Debounced 200 ms; queries `<2` chars don't fire. Results
  group **Features** (every menu destination, label/href/icon
  curated server-side) and **Cached SMC elements** (best-effort walk
  of `shared.smc_cache._section_caches` for items with a `name`
  field — translated to navigable URLs: `smc.explorer.<type>` →
  `/browse/<type>`, `engines.list` → `/engines/clusters`). Arrow
  keys + Enter navigate; Esc / outside-click closes. Backed by the
  new `GET /api/quick-search?q=...` endpoint (admin-protected,
  capped at 30 results, deduped).
- **Pinned bookmarks bar.** Star button on the topbar pins the
  current page (label inferred from the active sidebar entry or
  document title; icon inherited from the active link). Pin chips
  render in a thin bar between topbar and content; each has an X to
  remove. localStorage-backed (`flexedge_pins_v1`), per-browser, max
  12 (FIFO past that). Bar self-hides when empty. Star icon flips
  to `bi-star-fill` (yellow) when the current page is pinned.

No backend schema change. No new dependency. ~150 LoC across one
template file + 80 LoC for the search endpoint.

### Domain-Scoping audit + 7 fixes (2026-05-08)

Spec: [docs/DomainScopingAudit.md](docs/DomainScopingAudit.md). The
operator's mental model is "the topbar Domain selector controls
everything I see"; the audit surfaced six places where that wasn't
strictly true and one where the audit-trail couldn't tell you who did
what. All seven landed in this commit batch.

| # | Severity | Location | Fix |
| - | -------- | -------- | --- |
| D1 | **HIGH** — direct exfil via URL crafting | 4 DHCP cascade endpoints `/dhcp/api/tenants/<tid>/api-keys/...` | New `_assert_active_domain_match(tid, kid)` helper at the top of [webapp/dhcp_manager.py](webapp/dhcp_manager.py); 403 if URL IDs don't match `g.domain.api_key_id` / its tenant. |
| D2 | **MEDIUM** — cross-Domain data loss | DHCP `sweep_old_logs` and `cli/sweep_dhcp_logs.py` | New `domain_id` parameter on the sweeper (and on `shared.logging.sweep_old_logs`). Web button scopes to active Domain; CLI iterates every Domain explicitly so each gets its own audit row. New `--domain <slug>` flag for targeted sweeps. |
| A | LOW (defense-in-depth) | `webapp/app.py:1915` `_load_submission_in_active_domain` | `OptimizationSubmission.query.filter_by(id=sub_id, domain_id=g.domain.id).first_or_404()` — filter at query level instead of post-load check. |
| B | MEDIUM — log visibility leak | `webapp/app.py` `view_logs` | Removed the "show all my Domains" widen branch entirely. `/logs` is now strictly scoped to the active Domain (system-feature rows with `domain_id IS NULL` still visible — they're domain-agnostic bootstrap markers). Toggle removed from the template. |
| C | MEDIUM — visibility leak | `webapp/tls_manager.py` 3 cert listing routes | New `_certs_in_active_domain(domain_id)` helper using a `TLSDeployment` subquery (Path I, no schema change). Dashboard + certificates list scoped to it. Deploy form's cert dropdown intentionally NOT scoped (write-side picker; chicken-and-egg if you've never deployed in this Domain yet) — comment explains. |
| D3 | LOW (defensive comment) | `webapp/migration_dhcp_writer.py` | `DhcpReservation` has no `domain_id` column — Domain inherits via `scope_id → DhcpScope.domain_id`. Added a defense-in-depth note at the insert site so future refactors don't try to add a `domain_id=` kwarg to a column that doesn't exist. |
| E2 | Audit-trail gap | `webapp/tls_scheduler.py` `handle_renewal_webhook` | Bucket renewal results by `dep.domain_id`; emit one `audit("tls", "renew.cross_domain", ...)` row per affected Domain with the `engines=[...]` list and `deployed/failed/skipped` counts. Operators reading `/logs` in their Domain see exactly the renewals that touched THEIR engines, not a cryptic global "the cert renewed" line. |

Plus three secondary fixes folded into the same batch after the user
flagged related leaks:

- DHCP `credentials_list`, DHCP `scopes_list`, TLS `deploy_form` —
  the "Tenant" dropdown narrowed from `Tenant.query.all()` to just
  the one Tenant bound to the active Domain's API key. Operator
  never sees another Domain's Tenant in any picker.
- `/dhcp/scopes/<id>/leases` no longer redirects to `/dhcp/credentials`
  when no SSH credentials are enrolled. The route now renders the
  leases page in place with an inline empty-state alert that names
  the active Domain so a "creds enrolled under another Domain"
  mismatch becomes visible at a glance, plus a one-click button to
  the credentials wizard. Operator stays in their context.
- Browser link to `/browse/l3_firewalls` (Infrastructure → "Layer-3
  Firewall Engines") relabeled to "Engines" and hard-redirects to
  `/engines/clusters`. The legacy SDK-class-filtered explorer only
  showed the `Layer3Firewall` subclass, missing clusters / virtual
  engines / IPS / masters; the dedicated Engines page covers
  everything.

Intentionally cross-Domain (no change): admin portal Tenants /
Users / API Keys / Domains pages (Super Admin infrastructure
management), TLS certbot renewal webhook (host-level, fires across
Domains by design).

### Web UX hardening: AJAX error transparency + auth-redirect bounce (2026-05-08)

Two related fixes. Symptom that motivated them: operators seeing
*"Failed at stage network: SyntaxError: Unexpected token '<', '<!doctype'... is not valid JSON"*
in the credentials wizard whenever the server returned an HTML
response (Flask's default 500 page or the login redirect) to an
AJAX call.

- **`window.fetch` patch** in
  [webapp/templates/base.html](webapp/templates/base.html). When the
  response was redirected to `/login` or `/auth/`, OR the status is
  `401` / `403`, redirect the page to `/login?next=<current>` and
  throw so any caller `.catch` fires. Skip the bounce if we're
  already on a login-ish path (avoids loops). Patches `window.fetch`
  itself rather than only `fexFetch`, so raw `fetch(...)` callers
  (graph, scan watchers, TLS deploy form, DHCP credentials, etc.)
  benefit without per-template edits.
- **Generic AJAX exception handler** in
  [webapp/app.py](webapp/app.py). When any uncaught exception or
  `HTTPException` fires inside a request that looks AJAX
  (`X-Requested-With: XMLHttpRequest` or `Accept: application/json`),
  return JSON like `{"error": "TypeError: ...", "code": 500}`
  instead of Flask's HTML debug page. Non-AJAX requests fall through
  to the default HTML rendering. **Beneficial side-effect:** the
  pre-existing `tcp_probe` `NameError` in `credentials_apply` (top-
  level import was missing) is now visible as a clean error message
  instead of Flask's HTML 500 page that JS choked on. Fixed the
  import too: `tcp_probe` is now in the module-level
  `from webapp.dhcp_ssh import ...` block.

### Queue runner: SMC error humanizer (2026-05-08)

[shared/queue_runner.py](shared/queue_runner.py) `_mark_push_failed`
now runs the raw SMC error through `_humanize_smc_error()` before
persisting to `pending_changes.push_error_text` and the audit log.
First pattern covered: policy lock contention. Patterns matched
(case-insensitive substrings on the SMC error string):

- `policy is locked`
- `is currently locked`
- `currently locked by`
- `locked by another`
- `locked by user` / `locked by the user`
- `cannot obtain lock`
- `lock is owned by`
- `unable to obtain lock`

Any of those triggers prepended remediation:
*"Policy is locked by another SMC session — somebody is currently
editing it in SMC Management Client (or another automation holds the
lock). Ask the holder to commit or discard their changes, then retry
this row from /changes/. [raw: ...]"*. Raw SMC string preserved at
the end so debugging stays sharp. Anything unmatched falls through
unchanged. Single chokepoint means **every** queue handler — `install_ssh_rule`, `deploy_tls`, `create_*`, `update`, `upload_policy`, anything future — automatically inherits the friendlier message.

### Engines → Tools → Scan: VLAN sub-interface picker fix (2026-05-08)

The cascading interface picker on `/engines/tools/scan` was missing
every VLAN sub-interface — only physical parent interfaces appeared
in the dropdown. Three layers of bug, one root cause: the SDK
`PhysicalInterface.data.data` returns the SMC payload, but
`engine_inquiry._walk_interfaces` was reading `pi.data` directly
(without the second `.data` unwrap), then keying VLANs by a
`vlan_id` field that doesn't exist (the SDK encodes the VLAN id
inside the entry's `interface_id` as `"1.42"`).

Fixes in [webapp/engine_inquiry.py](webapp/engine_inquiry.py):

1. Unwrap `pi.data.data` like
   [webapp/smc_dhcp_client.py](webapp/smc_dhcp_client.py) already
   does for DHCP scope discovery.
2. Read VLAN identity from the entry's composite `interface_id`
   (`"1.42"`) and split on `.` to get `(parent_id="1", vlan_id="42")`.
3. Handle wrapped payloads (`{"physical_interface": {...}}`) +
   snake_case `vlan_interfaces` key variant — same defensive
   pattern as DHCP.

[webapp/engines_manager.py](webapp/engines_manager.py)
`api_cluster_interfaces` deduplicates on the composite
`(interface_id, vlan_id)` key (was just `interface_id`, which
collapsed every VLAN into the parent) and sorts iface-then-vlan
numerically. The picker form gains a hidden `vlan_id` input that
the JS syncs from each option's `data-vlan-id` so the scan-start
POST has both halves of the composite key.

Same fix benefits the cluster_detail Interfaces tab — VLAN IDs
finally render in their column.

### Engines → Tools → Scan history (Phases 1-3 of the spec) (2026-05-08)

Spec: [docs/Engines-ScanHistory.md](docs/Engines-ScanHistory.md).
Three phases of the four-phase plan landed in one session.
Phase 4 (scheduler) is deferred to a focused commit so the
in-process ticker thread under multi-worker gunicorn can be
lab-validated without entangling the rest of the work.

**Phase 1 — persistence + history list + detail + retention.**

- Two new tables in [webapp/models.py](webapp/models.py):
  `engine_scan_records` (one row per scan; comment, starred,
  source_correlation, scope keys, summary stats), `engine_scan_hosts`
  (one row per IP per scan with `ip_int` for numeric sort, port CSVs
  for compact storage). `db.create_all()` picks them up; no manual
  migration.
- New re-usable sub-package `webapp/scan_history/` with one public
  service API: `register_scan(domain, report, ...)`,
  `list_scans(domain, ...)`, `get_scan(domain, id)`, `set_comment`,
  `set_starred`, `delete_scan`, `bulk_set_starred`, `bulk_delete`,
  `get_settings`, `set_settings`. Any future feature that produces
  an `EngineScanReport`-shaped dataclass plugs in via
  `register_scan` and gets the entire UI for free.
- Routes at `/engines/scans/*` (Blueprint at
  [webapp/scan_history/routes.py](webapp/scan_history/routes.py)):
  history list with filters (engine / iface / starred / date) +
  bulk star + bulk delete + retention form, detail view with comment
  editor + star toggle + CSV export + IP-numeric-sorted host table
  with live filter, manual sweep button.
- Retention rotation: count or days mode (default `count = 20`,
  per-scope), starred always survive. Lazy hourly sweep fires when
  someone visits the history page.
- `engines_manager.tools_scan` wired to call `register_scan` on
  scan complete and redirect to `/engines/scans/<id>` so the
  operator lands on a URL that survives the in-memory 15-min TTL.
- Audit feature `engine_scan_history` registered in
  [webapp/app.py](webapp/app.py); every state change emits
  `audit("engine_scan_history", "scan.persist|comment|star|unstar|delete|retention.sweep|settings.update", ...)`.
- Engines sidebar gains "Scan history" sub-entry.

**Phase 2 — compare 2-10 scans of the same scope.**

- New [webapp/scan_history/compare.py](webapp/scan_history/compare.py)
  with pure-diff helpers: `CompareReport`, `HostTimeline`,
  `HostCell` dataclasses; `compare_scans(domain, ids)` fetches
  records + hosts in two queries, scope-checks `(engine, iface)`,
  sorts ASC by `started_at`, computes per-host port-set deltas vs
  the nearest previous-seen cell.
- `GET|POST /engines/scans/compare` accepts `scan_ids[]` from a
  POST form OR `?ids=1,2,3` for deep-linkable URLs.
- Compare button on the history list, with selection-aware JS:
  enabled only when 2-10 rows selected AND all share `(engine,
  iface)`. Cross-scope selection keeps it disabled with explanatory
  tooltip.
- Compare template: sticky-header table, IP rows × scan columns,
  reachability badges + open-port set with `+22` (newly open) /
  `−3389` (closed since previous) / `new` (first sighting) /
  `gone` (host disappeared) markers. "Diff only" toggle hides
  unchanged rows.

**Phase 3 — time graph.**

- New [webapp/templates/scan_history/graph.html](webapp/templates/scan_history/graph.html)
  with a vanilla SVG line renderer (~250 lines of JS, zero deps).
  Two series: *Online IPs* (solid green) + *Hosts w/ open* (dashed
  cyan). Per-point markers: ⭐ for starred, triangle for scheduled,
  dot for manual. Hover tooltip shows ts / scan id / counts /
  engine / iface / source / comment. Click any point → deep-link
  to `/engines/scans/<id>`. Auto-resize on window resize.
- `GET /engines/scans/graph` (HTML page) +
  `GET /engines/scans/graph.json` (data feed) — both honor
  `?engine=&iface=&days=` filters.
- New `aggregate_for_graph(domain, ...)` helper on the service layer.
- Vanilla SVG instead of Chart.js: zero deploy steps for the
  operator (no vendor download), works air-gapped, full control over
  click-through + per-point markers. Honors the
  `feedback_deployment_scenarios` standing rule (vendor functional
  assets locally — by avoiding the dependency entirely).
- "Time graph" sub-entry in the Engines sidebar.

### Engines → Tools → Scan landed (2026-05-07)

Engine-level network scan tool — pick a node + interface from the
cascading picker, run an active-discovery sweep against any target
range from that interface's vantage point. Operator guide:
[docs/Engines-ScanTool.md](docs/Engines-ScanTool.md). Plan-to-live
delta: ~5 h, no new external dependencies.

- **Decision blocker resolved.** Forcepoint NGFW BusyBox does NOT
  ship `nmap`, but `nc -z` (TCP zero-I/O scan), `nslookup`, `arping`,
  `ip neighbor show`, and `ip route get` are all there. The full
  feature builds on the existing tools — no static binary to bundle.
- **Generic background-job runtime** in
  [webapp/scan_jobs.py](webapp/scan_jobs.py): module-local `_JOBS`
  dict + `threading.Lock` + 15-min TTL eviction + per-user ownership
  check. Public API: `register_job` / `update_progress` /
  `increment` / `append_log` / `mark_done` / `mark_failed` /
  `spawn_runner` / `get_status` / `consume_report` / `discard`.
- **DHCP scan refactored.** [webapp/dhcp_scan_jobs.py](webapp/dhcp_scan_jobs.py)
  is now a thin wrapper around the shared runtime. Public API
  unchanged — DHCP routes import unchanged. Runtime is now
  feature-agnostic.
- **Engine scanner** [webapp/engine_scan.py](webapp/engine_scan.py):
  4-phase shell script — Phase 1 ICMP (parallel ping +
  `ip neighbor show` for MAC), Phase 2 arping fallback for
  ICMP-failed (L2 visibility), Phase 3 port scan (`nc -z -w1` per
  reachable IP × port), Phase 4 reverse DNS (`nslookup`). Output
  streams line-by-line for live progress. `parse_port_list()`
  handles comma / whitespace / range syntax (`1-1024`).
- **Routes** in [webapp/engines_manager.py](webapp/engines_manager.py):
  - `GET /engines/tools/scan` — picker / watcher / results dispatch
  - `POST /engines/tools/scan` — validate, build IP list, enforce
    caps + warn threshold, kick off background job
  - `GET /engines/tools/scan/status?id=X` — JSON poll target
  - `GET /engines/api/clusters/<engine>/interfaces` — cascading
    picker JSON: nodes (with `verified` flag) + interfaces (with
    attached subnet)
  - `GET /engines/tools/scan/<id>/csv` — export results as CSV
- **Template** [webapp/templates/engines/tools_scan.html](webapp/templates/engines/tools_scan.html):
  cluster→node→interface cascading picker (backed by the JSON
  endpoint), target-mode radio (subnet / single IP / custom range),
  ports input pre-filled with the curated default + reset/clear
  shortcuts + skip-port-scan checkbox, JS op-count estimator with
  warning gate, watcher card identical to DHCP scan, result table
  with ICMP / MAC / hostname / open-port columns + 5 filter buttons
  with live counters + click-to-sort + CSV export.
- **Default port set (TCP-only, locked):** 25 ports —
  `20, 21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 389,
  443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080`.
  /24 × default = 6,375 ops, fits under the 8000 warn threshold.
  UDP probing intentionally NOT supported in v1.
- **Limits:** 4096 hosts cap (= /20), 256 ports cap, 8000 ops soft
  warn, 16384 ops hard cap.
- **Audit** via `audit("engines", "scan_started" / "scan_complete",
  ...)` with the scan_id as `source_correlation_id`.

### Policy rules viewer: section detection fix + full-text search (2026-05-07)

- **Sections were silently rendered as rules.** The detection in
  `get_policy_rules` / `get_policy_nat_rules` checked
  `"section" in rule.typeof.lower()`, but in `fp-NGFW-SMC-python`
  v1.x both rules AND sections share the same `typeof`
  (`fw_ipv4_access_rule` / `fw_ipv4_nat_rule`). Sections are
  distinguished by data shape: they lack `sources` / `destinations`
  / `services` and carry their label in `comment` (where
  `create_rule_section(name=...)` writes it). The check now uses
  `Rule.is_rule_section` (the SDK's documented property) with a
  data-dict shape fallback for older SDK builds. Section headers
  render correctly again on `/policy/<name>`.
- **Full-text search bar** added to the policy rules viewer with
  the same UX as the Engines cluster-detail search: AND / OR token
  grammar (case-insensitive, mixed → AND), matched substrings
  highlighted in-place via `<mark.search-hit>`, rule + section
  counters update to "M of N" while a query is active. Section
  headers stay visible when any rule under them matches OR when
  the section name matches — preserves operator context. Esc
  clears, × button on the input, debounced 80 ms.

### DHCP Manager: subnet active-discovery scan (2026-05-07)

Active-discovery sweep that turns the **Active leases** page into a
richer view showing every device on the subnet, not just the ones
holding a DHCP lease. Operator guide:
[docs/DHCP-SubnetScan.md](docs/DHCP-SubnetScan.md).

- **New "Scan subnet" button** on `/dhcp/scopes/<id>/leases`. Opens a
  range-picker modal with three radio options:
  - **Scope (pool only)** — `dhcp_pool_start … dhcp_pool_end`. Default
    when subnet > /24.
  - **Full subnet** — every host in the CIDR minus
    gateway/network/broadcast. Default when subnet ≤ /24.
  - **Custom range** — operator-typed start/end IPs, server-validated
    to fit inside the subnet.

  Anything resolving to >256 hosts requires a confirmation checkbox.
  Hard cap at 4096 hosts (= /20) refuses /16 sweeps.
- **Async + live progress.** POST `/scan` starts a background daemon
  thread, redirects to `/leases?scan_id=X` which renders a watcher
  card (progress bar + 10-line rolling log). JS polls
  `/scan/status` every 800 ms; on `state=done` the page reloads with
  `?scan_id=X` so the leases route consumes the report and renders
  the enriched view.
- **6-state classifier.** Joining the scan results with
  `dhcpd.leases`, every IP is classified into:
  - `active` — lease + ICMP/ARP reply (healthy)
  - `leased-silent` — lease but no reply (powered off?)
  - `firewalled` — L2-visible (ARP) but drops ICMP
  - `free` — pool slot, no occupant
  - `active-untracked` — replies, no DHCP lease (static IP)
  - `firewalled-untracked` — L2-visible, drops ICMP, no lease
- **Promotion: in-pool scan responders join the upper table.**
  Discovered hosts whose IP falls inside the pool are merged into the
  upper lease table with `binding_state="no-lease"` so the operator
  can tick them and add to reservations like an ordinary lease.
  Out-of-pool responders stay in a separate "Discovered hosts (no
  DHCP lease)" card below.
- **Click-to-sort columns + numeric IP sort.** Every header in the
  upper table is clickable. **IP** uses a numeric octet-tuple
  comparator so `192.168.1.6` sorts before `192.168.1.69`. Other
  columns sort as text. Click toggles asc/desc; ▲/▼ indicator.
  Default = IP ascending, also enforced server-side.
- **Live counters on every filter button.** Lease-state filters
  (All / Active / Expired-free / Reserved / IP mismatch) plus five
  new discovery-state filters that appear after a scan
  (`active` / `silent` / `firewalled` / `untracked` /
  `untracked + firewalled`). Each button shows a badge with the
  count of matching rows, painted on `DOMContentLoaded` so the
  operator gets an at-a-glance overview without clicking. Discovery
  counters include rows from both tables (upper + lower card);
  clicking a discovery filter scopes both tables to that state.
- **MAC capture for ICMP_OK hosts.** Shell script reads the kernel
  ARP cache via `ip neighbor show <ip>` immediately after each
  successful ping, so ICMP-only responders also carry their MAC into
  the result and can be reserved without a follow-up arping.
- **New modules:**
  [webapp/dhcp_subnet_scan.py](webapp/dhcp_subnet_scan.py) —
  `enumerate_subnet_targets`, `enumerate_range_targets`,
  `_run_scan_streaming` (with `on_event` callback for live progress),
  `scan_subnet`, `classify`. Pure / no Flask deps.
  [webapp/dhcp_scan_jobs.py](webapp/dhcp_scan_jobs.py) — background
  job runtime: `start_scan` / `get_status` / `consume_report` /
  `discard`. Module-local `_JOBS` dict + `threading.Lock` + 15-min
  TTL eviction. Per-user ownership check on every access (no
  cross-user leaks).
- **Routes added** in [webapp/dhcp_manager.py](webapp/dhcp_manager.py):
  `POST /dhcp/scopes/<id>/scan`,
  `GET /dhcp/scopes/<id>/scan/status?id=X`. The existing
  `GET /dhcp/scopes/<id>/leases` route now also handles
  `?scan_id=X`: renders the watcher when running, consumes the
  report and renders the enriched view when done.

### Bug fixes (2026-05-06 → 2026-05-07)

- **Super Admin couldn't log in after Multi-Domain Revamp on
  existing data.** `_get_profiles_from_db` only iterated explicit
  `user_domain_access` grants, but the spec says Super Admin sees
  every Domain "including ones added later". Fixed: when
  `User.is_super_admin=True`, the profile list is built from every
  active Domain (with an active ApiKey). Self-heals deployments where
  the bootstrap admin had no UDA rows.
- **Container crash on import:** `shared/queue_runner._CREATE_DISPATCH`
  was defined at line 972 but referenced `_create_rule` /
  `_create_nat_rule` declared further down. Module-level dict literals
  evaluate at import time, so workers boot-looped with `NameError`.
  Moved the dispatch table to after the function definitions.
- **Jinja can't parse `<<` bitshift** in
  `templates/dhcp/leases.html` subnet-size calc — replaced with `**`.
- **`{% set %}` doesn't cross block scopes.** A var set in
  `{% block content %}` was read in `{% block extra_js %}`,
  producing `Undefined` and breaking `tojson`. Moved the value to
  the render context (passed from Python).
- **DHCP lease list rendered in lexicographic IP order** — server
  now sorts by numeric octet tuple before render, fixing cases where
  `192.168.1.6` sorted after `192.168.1.69`.

### Change Management Phase G — drift detector landed (2026-05-01)

Closes the loop on the `smc_objects` registry that Phase A introduced:
the registry's `last_seen_hash` is now actually *used* to flag SMC
elements that have been modified outside FlexEdgeAdmin.

- **New module [shared/smc_drift.py](shared/smc_drift.py).** Stable
  per-type SHA-256 hash (`compute_drift_hash`) over a whitelist of
  meaningful fields per `smc_type` (host, network, address_range, fqdn,
  tcp_service, udp_service, ip_service, icmp_service, group,
  service_group). Volatile keys (`link`, `key`, `mod_time`, `mod_user`,
  `read_only`) excluded; comments stripped of `[flexedge:audit ...]` +
  `[flexedge:mac=...]` markers before hashing so our own writes don't
  trip drift on the next scan.
- **Schema additions on `smc_objects`** (Phase G migration in
  [webapp/db_init.py](webapp/db_init.py)): `drift_state` ∈ {`unknown`,
  `clean`, `drifted`, `gone`}, `last_drift_check_at`, `drift_detail`.
  Idempotent ALTER TABLE — pre-existing rows default to `unknown` and
  baseline as `clean` on the first scan that successfully fetches them.
- **`scan_domain_drift(domain)`** opens ONE SMC session, walks every
  registry row for the Domain, fetches each by href via
  `Element.from_href`, classifies as clean / drifted / gone / errored,
  and updates the row in place. Per-row commits keep one bad element
  from poisoning the batch. Top-level audit entry summarises the run.
- **`reconcile_one(smc_object_id)`** re-baselines a drifted row to the
  current SMC state — the operator's "yes, accept this drift" button
  for intentional out-of-band changes. Audit-emits `drift.reconcile`.
- **UI: `/changes/drift`** — full list view filtered by drift_state
  (default: drifted + gone). Per-row Reconcile button (Domain Admin+).
  Scan-now button (Domain Admin+) runs `scan_domain_drift` synchronously
  and flashes a summary.
- **UI: drift summary card on `/changes/`** — appears when there's
  anything non-clean to flag, or when the registry has rows but never
  scanned. Counts + last-scan timestamp + deep-link to `/changes/drift`.
- **Per-row drift badge on listings** — new Jinja global
  `smc_drift_state(href_or_name)` returns `'drifted' | 'gone' | None`.
  Wired into the DHCP scope detail listing today; the same one-liner
  drops into TLS / Engines / explorer in a follow-up. Lookup is
  request-scoped (one query per page, lazy on first call).
- **Sidebar entry** — new "Drift detector" link under the "Change Queue"
  section, visible to Operator+.

**Phase E (Foundations + non-DHCP migration writers) and Phase G (drift
detector) close out the originally-planned Change Management surface.**
What remains is per-feature wiring of the bypass-queue capability into
admin UI workflows that haven't been touched yet, plus polishing the
Reconcile flow with a payload diff (deferred — current implementation
shows the "now" state, the previous state lives in platform_logs).

### Change Management Process — Phases A–D landed (2026-05-01)

Two-phase commit queue for every SMC mutation, gated by a four-tier
role model. Spec: [docs/ChangeManagementProcess.md](docs/ChangeManagementProcess.md).

- **Phase A — Foundation.** New `smc_objects` registry (the SMCRelated
  index, drives drift detection in Phase G) and `pending_changes` queue
  (state machine: QUEUED → PUSHED → APPLIED, plus ABORTED / PUSH_FAILED
  / CONFLICT). New role columns: `User.is_super_admin` (singular
  bootstrap admin) and `UserDomainAccess.role` ∈ {`global_admin`,
  `admin`, `operator`}. Idempotent `_phase_change_mgmt_a` migration
  renames yesterday's `is_global_admin` → `is_super_admin`, narrows
  Super status to the lowest-id admin, promotes other previous-admins
  to per-Domain `global_admin` so they keep power within their assigned
  Domains.
- **Phase B — Role enforcement.** New `webapp/auth_roles.py` with a
  five-tier `Role` IntEnum (VIEWER < DOMAIN_OPERATOR < DOMAIN_ADMIN <
  GLOBAL_ADMIN < SUPER_ADMIN). Decorators: `@super_admin_required`,
  `@global_admin_required`, `@domain_admin_required`,
  `@domain_operator_required` — each is "this tier or higher". Resolver
  `current_role_for_active_domain()` reads `User.is_super_admin` first,
  then `UserDomainAccess.role` for the active Domain; result cached on
  `g`. `user_manager.is_admin()` widened to accept all admin flavors so
  existing `@admin_required` decorators pass through unchanged. Sidebar
  split: Operator+ sees TLS / DHCP / Engines / Logs / Change Queue;
  Admin+ adds Admin Portal + Optimizer Review Queue.
- **Phase C — Push runner.** New `shared/queue_runner.py` with
  `push_one` / `push_batch` / `push_all_for_domain` / `abort_one` /
  `confirm_to_be_deleted` / `revoke_to_be_deleted` / `register_handler`.
  Halt-on-failure batch (Q4); auto cache invalidation after every PUSH
  (Q5); state-transition audit emission via `audit("changes", ...)` so
  every queue / push / apply / abort / push_failed lands on the unified
  Logs page with `source_correlation_id` for batch grouping. One
  proof-of-concept handler (`upload_policy`); the rest land in Phase E.
- **Phase D — Operator queue UI.** New blueprint `webapp/changes.py`
  at `/changes`. List view with filters (scope, state, source-batch,
  free-text search), Time vs Object views, conflict resolver with
  side-by-side payload diff + winner picker (Q11), `to_be_deleted`
  Confirm/Revoke buttons gated to Global Admin (Q12), per-row Push /
  Abort, bulk Push-all / Abort-all, sidebar entry with pending-count
  badge.
- **Gunicorn `--preload`** added to the Dockerfile to fix a worker race
  on first-boot table creation. `db.create_all()` was racing across the
  two workers — both saw "table doesn't exist", both tried to CREATE,
  the loser crashed. Preload imports the app once in the master before
  fork; defensive retry-on-already-exists wraps `create_all` for any
  non-preload deployments.
- **Round 2 questions** (Q11–Q14) captured in the spec doc with
  operator answers covering batch-promotion conflict semantics,
  operator-delete UX, invite flow, and `to_be_deleted` row TTL.

### Change Management Phase E.1 — Foundations (2026-05-01)

Phase E.2 (writer-by-writer enqueue conversion) is gated on Round 3
operator answers, so this slice ships the foundations needed when those
land.

- **Queue handlers (`shared/queue_runner.py`).** Added `create`,
  `update`, `delete`, `to_be_deleted`, `create_section`, `reload_dhcp`
  to the registry alongside the proof-of-concept `upload_policy`.
  `create`/`update`/`delete` dispatch by `smc_type` — `host` is the
  only type with a real implementation today (call paths through
  `webapp.smc_dhcp_client.host_create/update/delete`); other types
  return an explicit "no handler for type" error so a hand-crafted
  queue row can't silently no-op. `to_be_deleted` rejects direct push
  (must go via the queue's Confirm action which transitions to
  `delete` first). `create_section` and `reload_dhcp` are stubs that
  return "not implemented" until Phase E.2 wires their writers.
  Successful create / update reconciles the linked `SmcObject`
  registry row (upsert by `(domain_id, smc_href)`); delete retires
  the row. Registry maintenance is best-effort — failures log but
  never propagate.
- **Q12 strikethrough rendering.** New Jinja global
  `is_smc_to_be_deleted(href_or_name)` — request-scoped, lazy lookup
  against `smc_objects` filtered by active Domain, ONE query per page
  regardless of row count. Templates toggle the new
  `.smc-to-be-deleted` CSS class on listing rows; the row also gets a
  small "to be deleted" badge with a tooltip pointing the operator at
  the Change Queue. Applied to the DHCP reservation listing as a demo
  hook ([webapp/templates/dhcp/scope_detail.html](webapp/templates/dhcp/scope_detail.html));
  inert today (no writer populates `is_to_be_deleted=True` yet) and
  activates as soon as the first delete writer converts in Phase E.2.
- **Q13 invite-operator form.** New route
  `/admin/users/invite-operator` — Domain Admin (or higher) enters an
  Azure AD email + picks a Domain they admin, FEA creates the User
  row (display name fills in on first OIDC login) and grants
  `UserDomainAccess(role='operator')`. Super and Global Admin can
  invite into any active Domain; a Domain Admin only sees Domains
  where they hold `role IN ('admin', 'global_admin')`. Audit emits
  `audit('admin', 'user.invite_operator', ...)`. The Users listing
  shows the new "Invite Operator" button alongside "Add User", gated
  by `is_domain_admin`. Email-magic-link is parked as Q13a (TODO,
  needs SMTP + token table).
- **Round 3 questions raised** (Q15–Q22) — eight new dilemmas that
  surfaced as soon as we started planning per-writer conversion:
  auto-push UX for Domain Admin and above, listing UX for queued-
  but-unpushed rows, push-failure UX, cross-writer ordering between
  reservation create + Phase 4 deploy, TLS deployment chaining,
  migration import staging, `smc_objects` registry backfill strategy,
  and the strikethrough helper's row-vs-href identity model. All
  answers needed before Phase E.2 starts converting writers.

### Change Management Phase E.2 — DHCP reservation CRUD via queue (2026-05-01)

Round 3 (Q15–Q22) answered, first writer family converts to the queue.
Spec: [docs/ChangeManagementProcess.md § Phase E.2 implementation summary](docs/ChangeManagementProcess.md#phase-e2--implementation-summary-per-round-3-answers-2026-05-01).

- **DHCP reservation create / edit / delete** now go through
  `pending_changes`. New helper module
  [webapp/dhcp_reservation_queue.py](webapp/dhcp_reservation_queue.py)
  carries `enqueue_reservation_create / _update / _delete` and
  `try_auto_push_for_admins`. Routes
  [reservation_new / reservation_edit / reservation_delete](webapp/dhcp_manager.py)
  no longer call `host_create` / `host_update` / `host_delete` directly
  — they queue + auto-push for admins (Q15/a) or queue-only for
  Operators (who must visit `/changes/`).
- **Domain Admin and above:** UX feels identical to today —
  `push_one()` runs inline within the same request and the operator
  lands on the success page. The queue row becomes the audit trail.
- **Operator role:** the reservation appears in the scope listing
  with a `queued` badge and the operator gets redirected to
  `/changes/?source=dhcp_reservation:<id>`.
- **Push failure UX (Q17/b):** reservation row keeps a `push_failed`
  status; the scope listing shows the formatted SMC error inline
  below the row with a yellow **Retry** button that re-invokes
  `push_one()` on the same `pending_changes` row. New route
  `/dhcp/reservations/<id>/retry-push`.
- **Operator-submitted delete (Q12 + Q14):** flips
  `smc_objects.is_to_be_deleted=True` on the linked SMC Host so the
  Q12 strikethrough fires across listings; reservation row stays
  visible (struck-through) until a Global Admin Confirms / Revokes
  from `/changes/`. No auto-revoke (Q14).
- **Edits to a not-yet-pushed reservation** mutate the existing
  PendingChange's payload — no second queue row (Q16/a). Still-
  queued reservations support address/MAC edits via the same form.
- **SMC Host name auto-derived** as `dhcp-<engine>-<ip-dashed>`
  when the form name field is blank (Q16). Operator-supplied names
  honored as override.
- **Comment audit marker (Q21 feature request).** New module
  [webapp/smc_audit_marker.py](webapp/smc_audit_marker.py) — every
  successful `host` create / update stamps the SMC element's comment
  field with `[flexedge:audit ts=2026-05-01T... user=… prev="…20chars…"]`,
  visible in SMC Management Client without round-tripping through
  FlexEdgeAdmin. Idempotent (replaces previous marker, doesn't stack);
  coexists with the existing `[flexedge:mac=...]` marker. Operator-
  visible comment stays clean — both markers are stripped from
  `DhcpHostView.comment`.
- **Lazy registry population (Q21/a).** New module
  [shared/smc_registry.py](shared/smc_registry.py) with
  `register_smc_object_seen()` + `register_many()`. Wired into
  `webapp/smc_dhcp_client.host_get` and
  `list_scopes_for_engine` so the registry organically populates as
  operators use the DHCP feature. Best-effort: failures log + swallow,
  never break the surrounding read.
- **`reload_dhcp` queue handler removed** per Q18 — DHCP Phase 4 SSH
  push stays out of the queue (it's an SSH file write, not an SMC
  mutation; the existing scope-deploy button is unchanged).
- **Schema:** new `dhcp_reservations.pending_change_id` FK linking a
  reservation to the queue row controlling it when it's queued or
  push_failed (cleared on successful push). Idempotent migration in
  `webapp/db_init._migrate_post_create`.
- **Status states added** to `dhcp_reservations.status`: `queued`
  (waiting for push) and `push_failed` (push attempted, SMC rejected).
  No DB schema change needed — column was already a string.
- **What's next in E.2:** TLS deployment writer (Q19/b — single row,
  internal orchestrator with sub-action list); migration import
  writer (Q20 — direct submit to main queue, collapsed-with-expand
  row UI; descopes the originally-planned Phase F migration_review
  staging); DHCP credentials rule install/remove; reservation
  bulk-delete; broader `register_many` rollout (TLS, explorer,
  engine_inquiry).

### Change Management Phase E.2 — bulk-delete + registry rollout (2026-05-01)

Second slice of E.2 — completes DHCP reservation queue coverage and
rolls the lazy `smc_objects` registry out to the busiest read paths.

- **DHCP reservation bulk-delete via queue.** Operator selects N rows +
  ticks "also delete SMC Host" → one PendingChange per reservation,
  all sharing a `dhcp_reservation_bulk:<scope>:<token>` correlation
  id so `/changes/?source=<corr>` shows the whole group. Domain Admin
  and above hit `push_batch` (halt-on-failure per Q4 — first SMC
  rejection halts the batch, remaining rows stay QUEUED for inspect /
  resolve / retry; partial-success summary in the flash). Operators
  enqueue all rows as `to_be_deleted` (the linked SMC Hosts get
  `is_to_be_deleted=True` so Q12 strikethrough fires across listings
  while a Global Admin Confirms each from the queue UI). DB-only
  bulk-delete (operator unticks "also delete SMC Host") still fires
  immediately — no SMC mutation, no queue. Reservations that were
  still QUEUED (never pushed) get their in-flight create change
  aborted in one shot, the DB row dropped — no SMC delete needed
  since the Host doesn't exist there yet.
- **Lazy `smc_objects` registry rollout** — `register_many()` wired
  into three high-traffic read paths so the registry organically
  populates on every operator click:
  - [webapp/engine_inquiry.list_clusters](webapp/engine_inquiry.py)
    — registers every engine seen on `/engines/clusters`.
  - [webapp/smc_tls_client.list_engines](webapp/smc_tls_client.py)
    and `list_tls_credentials()` — registers engines + TLS credentials
    seen during TLS Manager flows.
  - [webapp/smc_client.list_elements](webapp/smc_client.py)
    — registers every Host / Network / Service / Group / etc. seen
    on `/browse/<type>` explorer pages, with the explorer's plural
    `type_key` mapped to a singular `smc_type` label (`hosts` →
    `host`, `tcp_services` → `tcp_service`, etc.).
  - All three call sites are best-effort (failures log + swallow
    in the registry helper) and add zero load when there's no
    active Domain (CLI invocations).

### Change Management Phase E.2 — DHCP credentials rule via queue (2026-05-01)

Third slice of E.2 — converts the SSH-allow rule install/remove +
force-policy-install operator buttons to go through the queue.

- **Two new queue operations** registered in
  [shared/queue_runner.py](shared/queue_runner.py):
  - `install_ssh_rule` — bundle handler (Q19/b internal-orchestrator
    pattern): find-or-create source Host + dest Hosts; create or
    detect rule in the engine's installed policy; persist the
    `DhcpEngineSshAccess` row; reconcile the linked `SmcObject`
    registry entry for the rule; upload the policy. ONE queue row,
    `applied=True` on success because the policy upload activates
    on the engine.
  - `remove_ssh_rule` — bundle handler: remove the rule from the
    policy + upload the policy. The DB-side
    `DhcpEngineSshAccess` row is dropped by the calling route
    after a successful push (so retry semantics stay clean — a
    failed first attempt leaves the access row so retry can find
    the policy/rule names).
- **New helper module:**
  [webapp/dhcp_credentials_queue.py](webapp/dhcp_credentials_queue.py)
  — `enqueue_install_ssh_rule`, `enqueue_remove_ssh_rule`,
  `enqueue_policy_upload`, `try_auto_push`. All reuse the same
  `source_correlation_id` shape (`dhcp_credentials_rule:<engine>` /
  `dhcp_credentials_policy:<engine>`) so a sequence of operator
  actions on the same engine groups cleanly on `/changes/`.
- **Three routes converted** in [webapp/dhcp_manager.py](webapp/dhcp_manager.py):
  - `POST /credentials/rule/install` — enqueue + auto-push for
    Domain Admin+. Source-IP drift detection still happens in the
    route (refuses install before enqueueing if drift is detected).
    Queue change is the audit record; on success the AJAX wizard
    sees the same flash + state-refresh as before.
  - `POST /credentials/rule/remove` (via `_do_rule_teardown`) —
    enqueue + auto-push. The local access row is deleted only
    after the push succeeds, so a push failure leaves both the
    access row AND the queue row available for Retry.
  - `POST /credentials/policy-install` — enqueue an `upload_policy`
    row (reuses the Phase C handler) + auto-push. Same audit /
    retry benefits.
- **Source-IP drift recovery** (`/rule/source/overwrite` and
  `/rule/source/add`) intentionally stays out-of-queue. They're
  one-shot fixes on an already-broken rule and queueing would just
  add latency without meaningful audit benefit (the `_log_activity`
  trail already covers it).

### Change Management Phase E.2 — DHCP migration import via queue (2026-05-01)

Fourth slice of E.2 — addresses the operator's original complaint that
started this whole spec ("the system says is done but I don't see it
in real"). Migration import no longer calls SMC directly; it stages
the batch in the Change Queue for explicit operator push.

- **`webapp/migration_dhcp_writer.py` rewritten** per Q20:
  - Drops the per-scope SMC session and the `host_create` / `host_update`
    direct calls.
  - Drops the rollback machinery (`created_hosts` tracking,
    `_rollback_created_hosts`, `_try_delete_host`) — the queue IS the
    rollback. A push failure leaves a `push_failed` row that operators
    can Retry or Abort from the Change Queue.
  - Inserts each `DhcpReservation` in `status='queued'` with `source=
    "migration:<project_id>"`, then enqueues a
    `pending_changes(operation='create', smc_type='host')` row sharing
    `source_correlation_id="migration:<project_id>"`.
  - Conflict-overwrite path enqueues an `update` row (was
    `host_update` direct call) with `audit_previous_value` carrying
    the prior IP for the in-SMC comment marker.
  - Returns two new fields in the result dict (`changes_enqueued` +
    `correlation_id`) so the import-summary UI can link to the
    queue.
- **Migration import-summary UI** (`webapp/templates/migration/import.html`)
  surfaces the staged batch with a prominent CTA:
  *"N DHCP reservation change(s) staged in the Change Queue. They are
  queued, not yet pushed to SMC. [Open Change Queue]"*. Replaces the
  previous "X reservations created" — the operator now sees explicitly
  that *nothing has hit SMC yet* and where to go next.
- **Phase F descoped** per Q20. The originally-planned
  `scope='migration_review'` queue isn't built — migration writes
  directly to the main queue with a shared correlation id, and the
  Change Queue UI's existing source-filter + collapsed-with-expand
  rendering handles the "review batch before push" workflow.
- The non-DHCP migration writer (`webapp/smc_writer.py` for FortiGate
  hosts/networks/services/rules) still calls SMC directly. Conversion
  needs new queue handlers for `network`, `service`, `service_group`,
  `rule`, `nat_rule` types — deferred to a focused follow-up.

### Change Management Phase E.2 — TLS deployment via queue (2026-05-01)

Fifth slice of E.2 — converts the TLS Manager deployment pipeline to
the Q19/b "single queue row + internal orchestrator + sub-action list"
pattern.

- **`deploy_tls` handler** registered in
  [shared/queue_runner.py](shared/queue_runner.py). Bundle: imports
  the TLS credential, creates source + dest Host elements, assigns
  the credential to the engine, finds-or-creates the policy rule,
  uploads the policy. ONE queue row, `applied=True` on success
  (the policy upload activates on the engine). Persists the
  populated `DeployResult` back into the `TLSDeployment` row +
  `TLSDeploymentLog` entry just like the legacy `run_deployment`
  did, then writes the `steps[]` array into the change's
  `payload_json` so the queue UI can render it.
- **`webapp/tls_deployer.py` refactored.** New
  `execute_deployment_inside_session(dep, fullchain, privkey)` runs
  the 5-step pipeline assuming an SMC session is already open (used
  by the queue handler — the runner opens its own session). The
  legacy `execute_deployment(dep, smc_cfg, ...)` now opens its own
  session and delegates here, so it stays usable for any
  out-of-queue caller.
- **`/tls/deploy/<id>/execute` route converted** in
  [webapp/tls_manager.py](webapp/tls_manager.py). Domain Admin+ gets
  inline auto-push (Q15/a) — UX feels identical to today, including
  the `tls/deploy_execute.html` step-by-step result table. Push
  failure surfaces the SMC error and leaves the queue row available
  for Retry from `/changes/`. Non-admin path (defensive — this is
  admin-only normally) queues + redirects to the queue.
- **Queue UI sub-action display.** New `from_json` Jinja filter
  registered in [webapp/app.py](webapp/app.py). The Change Queue's
  expanded detail panel
  ([webapp/templates/changes/_rows_table.html](webapp/templates/changes/_rows_table.html))
  parses `payload.steps` and renders an ordered list with per-step
  status badges (`ok` / `failed` / `warning`) so the operator sees
  *exactly which sub-step failed* without leaving the queue page.
  Q19/b answer satisfied: "ONE queue row but listing the actions in
  the order in which they will be instantiated."
- The same expanded-detail rendering also benefits future bundle
  handlers (`install_ssh_rule` already exposes a similar shape;
  Phase E.2 follow-up handlers for non-DHCP migration will too).

### Change Management Phase E.2 — Bypass Queue (per-domain, per-user) (2026-05-01)

Per-feature, per-domain, per-user "bypass queue" toggle. When enabled
for a (user, domain, feature) triple, the user's actions on that
feature in that domain skip the queue review model — they auto-push
within the same request and the queue row is deleted on success
(transient). Audit log entry stays. Failed pushes leave the row
visible so the operator can retry from `/changes/`.

- **Schema** — new `feature_bypass_settings` table
  ([webapp/models.py:FeatureBypassSetting](webapp/models.py)). Two
  row shapes coexist:
  - `(domain_id=X, user_id=NULL, feature=F, enabled)` — domain
    capability flag. Permission gate: when ON, Domain Admins of X
    are allowed to grant per-user bypass for F. Toggling does NOT
    change operator behavior on its own.
  - `(domain_id=X, user_id=Y, feature=F, enabled)` — per-user
    override. The operative bit: when ON, user Y's actions on F in
    X bypass the queue. Default for everyone everywhere is OFF
    (queue is the default).
- **Lookup** — [shared/queue_settings.py](shared/queue_settings.py)
  with `should_bypass_queue(feature, domain=None, user_email=None)`,
  `is_capability_enabled(domain, feature)`,
  `can_edit_capability(domain, feature)`,
  `can_edit_user_bypass(domain, feature)`, plus the mutators
  `set_capability` and `set_user_bypass`. Resolution is most-specific
  wins: per-user row first; otherwise False. Domain capability is
  consulted only by the UI permission helper, never by the bypass
  decision itself.
- **Authority cascade** —
  - Domain capability flag: Domain Admin in the Domain, Global
    Admin, Super Admin can flip.
  - Per-user override: Super and Global Admins can always edit;
    Domain Admins can edit only when domain capability for that
    feature is ON.
  - Operators: read-only (badge tells them when they're in bypass
    mode for a feature in this Domain).
- **Bypass feature registry** — V1 covers the four converted
  features: `dhcp_reservation`, `dhcp_credentials`, `tls_deploy`,
  `migration_dhcp`. The registry is independent of `feature_source`
  / `platform_log` feature names so bypass naming is finer-grained.
- **Wiring** — every existing converted enqueue helper now checks
  `should_bypass_queue(...)`:
  - [webapp/dhcp_reservation_queue.try_auto_push_for_admins](webapp/dhcp_reservation_queue.py)
    — admin OR bypass triggers inline push; on success when bypass
    applies, the queue row is deleted and a
    `<feature>.<op>.bypass_queue` audit marker is emitted.
  - [webapp/dhcp_credentials_queue.try_auto_push](webapp/dhcp_credentials_queue.py)
    — same pattern.
  - [webapp/tls_manager.deploy_execute](webapp/tls_manager.py) —
    same; identifiers captured before deletion so the success flash
    still works.
  - [webapp/app.py](webapp/app.py) migration-import path —
    when bypass is on, calls `push_batch` on the whole correlation
    group + deletes successful rows + emits per-row audit markers.
    Failed rows stay so the operator can recover from `/changes/`.
- **UI** —
  - `/admin/log-settings` extended with a "Bypass Queue — domain
    capabilities" matrix for the active Domain. Domain Admin sees
    only their own Domain (toggles disabled cross-Domain); Super /
    Global Admin can edit any Domain via the topbar switcher.
  - `/admin/users/<id>/edit` gets a "Per-feature Bypass" panel
    below the user form: a Domain × Feature matrix of toggles,
    each disabled when the editor isn't allowed to flip that
    combination (with a tooltip explaining why). New POST route
    `/admin/users/<id>/bypass` saves it.
  - New Jinja global `bypass_active(feature)` (request-scoped,
    memoized on `g`). Renders a small "Bypass active" badge on
    the DHCP scope detail page, the DHCP credentials wizard, and
    the TLS deploy execute page so operators see when their next
    action will commit immediately.
- **Audit emission** — every toggle change emits
  `audit("admin", "queue_bypass.capability"|"queue_bypass.user", ...)`.
  Each successful bypassed push emits
  `audit("<feature>", "<operation>.bypass_queue", ...)` with the
  source correlation id preserved, so log queries can find every
  action that ran in bypass mode.

### Change Management Phase E.2 — FortiGate object import via queue (2026-05-01)

Seventh slice of E.2 — converts the non-DHCP migration writer's
object creation path (hosts / networks / address ranges / FQDNs /
services / groups / NAT hosts) to enqueue. Rules and NAT rules
remain on the legacy direct path — they need policy + section +
position model work that warrants its own focused conversion.

- **New queue handlers** in [shared/queue_runner.py](shared/queue_runner.py):
  `network`, `address_range`, `fqdn`, `tcp_service`, `udp_service`,
  `group`, `service_group`. Joins the existing `host` handler.
  Refactored `_handle_create` to dispatch via a `_CREATE_DISPATCH`
  table so adding new types is a one-line registration. Each handler:
  - Parses the type-specific payload + stamps the Q21 audit comment
    marker (`[flexedge:audit ts=… user=…]`) into the SMC element's
    `comment` field.
  - Calls the SMC SDK's `Class.create(...)` and reconciles the
    linked `SmcObject` registry row.
  - Treats "already exists" / "must be unique" / "duplicate" as
    soft success — the migration importer is now idempotent.
    Re-running the same import produces zero churn.
  - Group handlers resolve members from the names list across the
    candidate SMC classes (Network / Host / AddressRange / Group /
    DomainName for address groups; TCPService / UDPService /
    ServiceGroup for service groups). Unresolvable members are
    skipped with a note in the queue row's `detail`.
- **New helper module**
  [webapp/migration_object_writer.py](webapp/migration_object_writer.py)
  exposes `enqueue_object_imports(parsed_objects, dedup_results,
  domain, project_id) -> dict`. Stages every selected object as a
  queue row in five tiers (addresses → services → address groups →
  service groups → NAT hosts). The natural `created_at` push order
  honors group dependencies — members push before groups, and
  halt-on-failure stops the cascade if a member create fails so
  groups don't try to push with unresolvable members.
- **Migration import route** ([webapp/app.py](webapp/app.py))
  swaps `smc_writer.create_objects(parsed, dedup, cfg)` for the new
  enqueue helper. Two parallel correlation ids are surfaced:
  `migration_dhcp_correlation_id` (DHCP reservations from the prior
  slice) and `migration_object_correlation_id` (FortiGate objects).
  Both use the prefix `migration:<project_id>`, so
  `/changes/?source=migration:<id>` shows the whole import grouped.
- **Bypass mode** — new `migration_object` feature in the bypass
  registry. When enabled for the (user, domain) pair, `push_batch`
  runs immediately on the object batch, successful rows are
  deleted, and `<op>.bypass_queue` audit markers are emitted.
  Failed rows stay queued for Retry from `/changes/`.
- **Migration import-summary template**
  ([webapp/templates/migration/import.html](webapp/templates/migration/import.html))
  surfaces the object batch with the same "Open Change Queue" CTA
  pattern as the DHCP path. Includes a per-type breakdown
  ("host: N, network: M, ...") so the operator sees the shape of
  what was staged.
- **What's still on the legacy direct path:**
  - `smc_writer.create_rules` (firewall rules) — needs a `rule`
    queue handler + a real `create_section` handler.
  - `smc_writer.create_nat_rules` — needs a `nat_rule` handler.
  - `smc_writer.create_vpn_infrastructure` — VPN profiles +
    gateways + policies; complex enough to warrant its own
    dedicated turn.

### Change Management Phase E.2 — FortiGate rule + NAT import via queue (2026-05-01)

Eighth slice of E.2 — converts the firewall rule + NAT writer paths
to enqueue. Combined with the prior object-import slice this means
every FortiGate import sub-batch (DHCP / objects / rules / NAT)
lands in the change queue with full audit trail and dependency-
honoring push order. Only VPN remains on the direct path.

- **New queue handlers** in [shared/queue_runner.py](shared/queue_runner.py):
  - `rule` — creates a firewall rule in a policy's `fw_ipv4_access_rules`
    (with optional section). Resolves source / destination / service
    names across every candidate SMC class at push time; unresolvable
    members fall back to `"any"` (legacy semantics preserved).
  - `nat_rule` — creates a NAT rule in `fw_ipv4_nat_rules`. Pre-
    resolves SNAT/DNAT IPs → SMC Host names at enqueue time via the
    import's `nat_host_map`, so the handler only sees names.
  - `create_section` — replaces the prior "not implemented" stub.
    Calls `policy.fw_ipv4_access_rules.create_rule_section(...)`.
    Idempotent on already-exists.
  - All three stamp the Q21 audit comment marker, treat
    "already exists" as soft success (idempotent re-import), and
    reconcile `SmcObject` so the registry covers rules + sections.
- **Helper** `_ensure_firewall_policy(policy_name)` does idempotent
  find-or-create on the `FirewallPolicy` at the start of each
  rule / section / NAT handler so a missing policy doesn't crash the
  cascade. Plus shared `_resolve_element_name` /
  `_resolve_service_name` / `_resolve_member_list` helpers used by
  both rule + NAT handlers (and exposed for any future writer that
  needs the same lookup pattern).
- **New helper module**
  [webapp/migration_rule_writer.py](webapp/migration_rule_writer.py)
  with two functions:
  - `enqueue_rule_imports(converted, domain, project_id, policy_name)`
    — stages sections + rules in dependency order. For each section
    in `converted_rules.sections`: enqueue the section first, then
    every selected rule under it. Push runner's natural created_at
    order ensures sections push before their rules.
  - `enqueue_nat_rule_imports(converted, dedup, domain, project_id,
    policy_name)` — stages NAT rules with pre-resolved Host names.
- **Migration import route** ([webapp/app.py](webapp/app.py))
  swaps `smc_writer.create_rules(...)` → `enqueue_rule_imports(...)`
  and `smc_writer.create_nat_rules(...)` → `enqueue_nat_rule_imports(...)`.
  All four migration tiers (DHCP, objects, rules, NAT) share the
  prefix `migration:<project_id>` for the source correlation id.
- **Bypass mode** — two new features registered: `migration_rule`,
  `migration_nat`. Refactored the inline bypass-push logic from the
  prior slices into a shared helper `_bypass_push_migration_batch`
  in [webapp/app.py](webapp/app.py) that DHCP / objects / rules / NAT
  all delegate to. Single source of truth for "find queued rows in
  this batch, push, delete-on-success, audit-mark."
- **Migration import-summary template**
  ([webapp/templates/migration/import.html](webapp/templates/migration/import.html))
  consolidated into ONE alert showing the total enqueued count +
  per-tier breakdown (objects with by-type detail, sections + rules,
  NAT rules). Single "Open Change Queue" link points at the unified
  `migration:<id>` view since all tiers share the correlation id —
  operator now sees the whole import as one logical batch.
- **Push order in the unified queue** is dependency-honored without
  any explicit `scheduled_after` plumbing because the migration
  enqueue is single-threaded inside the import request:
  1. Objects (host / network / address_range / fqdn / tcp_service /
     udp_service / group / service_group / NAT host)
  2. Rule sections per converted section
  3. Firewall rules under each section
  4. NAT rules
  Halt-on-failure (Q4) stops the cascade so dependent rows don't
  push if a member fails.

### Change Management Phase E.2 — FortiGate VPN import via queue (2026-05-01)

Ninth slice of E.2 — converts the last remaining direct-write
migration path. **Phase E.2 complete:** every mutating writer in
FlexEdgeAdmin goes through the queue.

- **New `deploy_vpn` queue handler** in [shared/queue_runner.py](shared/queue_runner.py).
  Q19/b internal-orchestrator pattern (same as `deploy_tls`):
  ONE queue row per VPN config, the handler runs the 6-step
  pipeline inside the queue runner's SMC session and persists per-
  step status into `payload.steps[]` so the queue UI's expanded
  detail panel renders the same per-step badges as TLS.
- **New helper module** [webapp/migration_vpn_writer.py](webapp/migration_vpn_writer.py)
  carries the orchestration body in
  `execute_vpn_pipeline_inside_session(config, engine_name)` and
  the enqueue entry in `enqueue_vpn_imports(...)`. The 6 steps:
  - Step 1: VPN profile (find-or-create with crypto capabilities,
    `sa_life_time` and `tunnel_life_time_seconds` from config).
  - Step 2: External gateway (find-or-create with `trust_all_cas=True`).
  - Step 3: External endpoint (remote peer IP on the gateway).
  - Step 4: VPN site + member networks (resolves remote subnets
    against existing Network/Host elements; creates `FGT-VPN-<name>-
    <subnet>` placeholders for unresolvable subnets).
  - Step 5: PolicyVPN container (with `nat=True` + the VPN profile).
  - Step 6: Topology — open + add satellite gateway + add central
    gateway (engine) + save + close. Skipped on re-import if the
    PolicyVPN already existed, to avoid appending duplicate gateway
    entries.
  - Each step is `ok` / `warning` / `failed` in the per-step trace.
    Idempotent on already-exists. `vpn_site` falls back to a
    warning when no resolvable subnets exist (rather than failing
    the whole VPN config).
- **Migration import route** ([webapp/app.py](webapp/app.py)) swaps
  `smc_writer.create_vpn_infrastructure(...)` →
  `enqueue_vpn_imports(...)`. Reuses the shared
  `_bypass_push_migration_batch` helper.
- **Bypass mode** — new `migration_vpn` feature in the bypass
  registry. Same per-user, per-domain semantics as every other
  feature; when enabled, the VPN batch pushes inline + successful
  rows are deleted + `vpn.deploy_vpn.bypass_queue` audit markers
  emitted.
- **Migration import-summary template** updated to count VPN
  configs in the unified CTA's total + per-tier breakdown. All 5
  migration tiers (DHCP / objects / rules / NAT / VPN) share the
  `migration:<project_id>` correlation id so the operator opens
  ONE queue page that shows the full import.
- **Phase E.2 complete.** Every mutating writer FlexEdgeAdmin owns
  now goes through the queue:
  - DHCP reservation CRUD (single + bulk) — slice 1 + 2
  - DHCP credentials rule install/remove + force-policy-install — slice 3
  - DHCP migration import — slice 4
  - TLS certificate deployment — slice 5
  - Bypass-queue (per-domain, per-user) — slice 6
  - FortiGate object import — slice 7
  - FortiGate firewall rule + section import + NAT rule import — slice 8
  - FortiGate VPN topology — slice 9
- **What's next:** Phase G (drift detector) — compares
  `smc_objects.last_seen_hash` vs live SMC fetch. The lazy-on-read
  registry rollout from earlier slices already covers what
  operators touch; drift detection now has data to work with.

### Cross-Domain leak hardening + UX improvements (2026-05-01)

- **Cross-Domain read scoping** — DHCP, TLS, Optimizer list views now
  filter by `g.domain.id` instead of `.query.all()`. Optimizer
  submission detail/decide routes patched to 404 on cross-Domain row
  access (audit found admins in Domain A could view/decide rows from
  Domain B via direct URL).
- **Topbar Domain switcher** — dropdown in the upper right listing
  every Domain the user has `UserDomainAccess` for. Switching invokes
  `/switch-domain` which invalidates the SMC read cache so the next
  page load is fresh.
- **Single-profile auto-skip** — Azure AD callback for users with one
  profile sets `active_domain` immediately and lands on `/`, skipping
  the legacy `/select-domain` step entirely.
- **Dual-frame scroll layout** — sidebar and main content scroll
  independently; topbar is sticky in the main pane. Sidebar `scrollTop`
  persisted to `sessionStorage` so navigation doesn't reset the menu
  position.

### Platform log unification — standing rule satisfied (2026-05-01)

The standing rule "every feature funnels its audit + operational
entries through one platform log system" (memory:
`feedback_logging_standing_rule`) is now operative.

- **New `platform_logs` table** (`id, timestamp, level, feature, action,
  status, user_email, target, detail, domain_id,
  source_correlation_id`). Replaces the per-feature
  `dhcp_activity_logs` + `tls_activity_logs` writes. Existing legacy
  rows are backfilled into `platform_logs` once at boot via
  `_phase_log_unification`; legacy tables remain read-only.
- **New `platform_settings` table** (key/value config). Known keys:
  `log_mode` ∈ {`normal`, `verbose`}, `log_retention_days`,
  `feature_log_<name>` ∈ {`on`, `off`}, `legacy_logs_migrated`.
- **New `shared/logging.py`** — `audit(feature, action, ...)`, `op(...)`,
  `register_feature(name, label)`, `is_feature_enabled(feature)`,
  `current_log_mode()`, `current_retention_days()`, `sweep_old_logs()`.
  Writes never break the request — `_write` is fully wrapped in
  try/except with rollback. `op()` only persists when log mode is
  `verbose`.
- **Existing helpers repointed** — `_log_activity` in `dhcp_manager.py`,
  `tls_manager.py`, and `_log_activity_engines` in `engines_manager.py`
  now call `audit("dhcp"/"tls"/"engines", ...)` and route to the
  unified table.
- **Phase 0 gate cross-table reader** — `is_phase0_validated()` and
  `get_phase0_validation()` check BOTH `platform_logs` AND legacy
  `dhcp_activity_logs` so the Phase 4 deploy gate stays effective
  across the cutover.
- **New `/logs` page** (admin only) — multi-feature filterable viewer
  with date / status / level / free-text search, "active Domain only"
  toggle for cross-Domain visibility, expandable detail panels.
- **New `/admin/log-settings` page** — log mode toggle, retention
  days input, per-feature on/off matrix with row counts, manual sweep
  button.
- **Sidebar reorg** — "Activity Logs" moved out of DHCP Manager into a
  new top-level "Logs" section that also hosts DHCP/TLS deployment
  history and log settings.
- **Legacy `/dhcp/activity`** redirects to `/logs?feature=dhcp&active_only=1`.

### Multi-Domain Revamp landed (2026-04-29 → 2026-04-30)

Operators now see **Domain** as the only scope unit. Each Domain is one
`(api_key, smc_domain_name)` pair with its own slug, display name, and
CLI back-compat token. The legacy two-step "Profile → SMC domain" flow
is gone — a single profile pick auto-sets the SMC admin-domain and
lands the operator on the dashboard.

- **Schema**: every feature table is keyed by `domain_id`. SMC config
  (`smc_url`, `verify_ssl`, `timeout`, `api_version`,
  `flexedge_source_ip`) absorbed onto `api_keys`. `user_tenant_access`
  table dropped. `tenants` table kept admin-internal as a legacy
  compat shim for the API Keys form's find-or-create on URL match.
  Vestigial `tenant_id` / `api_key_id` columns on feature tables sit
  populated but unread (SQLite can't `DROP COLUMN` under composite
  UNIQUEs without table recreation — deferred to a focused commit).
- **Admin Portal**: API Keys + Domains + Users as the three primary
  pages. New API Keys form takes the SMC URL + SSL/timeout/api_version
  /source_ip directly and auto-creates a default Domain. Domains CRUD
  page added. Users form switches to a per-Domain checkbox grid +
  default radio. Hard-delete API keys (refuses if Domains still
  reference the key).
- **Bulk-delete reservations** on the scope detail page (select-all
  checkbox + optional "also delete SMC Host elements" toggle).
- **`/select-domain` skipped** after profile pick — Domain pins the
  SMC domain.
- **SQLite FK enforcement on**: `PRAGMA foreign_keys=ON` registered as
  a SQLAlchemy `connect` event listener so declared FKs are actually
  enforced (SQLite default is OFF per-connection).
- Plan + per-section operator decisions:
  [docs/MultiDomainRevamp.md](docs/MultiDomainRevamp.md).

### DHCP scope discovery — Address-Range element refs

The pool resolver now handles three SMC payload shapes:

1. Inline `dhcp_address_range = "start-end"` (most common).
2. Per-node list `dhcp_range_per_node[*].dhcp_address_range`.
3. Element reference via `dhcp_range_ref` (Forcepoint NGFW 7.1 shape
   observed on GUYFW interface 0.0.2) — resolved by fetching the SMC
   `AddressRange` element and reading its `data.ip_range`. Older
   `dhcp_address_range_ref` / `address_range_ref` shapes also covered.

Per-interface error isolation in `list_scopes_for_engine` so one bad
payload no longer aborts the whole traversal silently. Always-on per-
scope INFO log + per-failure WARNING dump of the raw cfg dict so
the next missing-shape report can pinpoint the field name without a
debug-endpoint round-trip.

### Removed — Sandbox

Per the operator's MultiDomainRevamp Q1 answer, Sandbox is gone:

- `GET /sandbox` HTML route + `GET /api/sandbox` JSON route
- `smc_client.sandbox_rules_check()`
- `webapp/templates/sandbox.html`
- Sidebar nav link + dashboard quick-action card + per-policy and
  per-rule-page Sandbox buttons

The Optimizer (live findings on a policy) and the Migration Manager
(import-time validation) cover rule validation with strictly more
depth than the legacy Sandbox summary.

### Added — Engines feature Phase A (read-only inventory + cache + search)

- **`/engines/clusters`** — engine inventory, served through the new
  process-local SMC read cache (`shared/smc_cache.py`). Header shows
  "cached · N min ago" or "fresh from SMC" + a `?refresh=1` button
  forces a live re-fetch.
- **`/engines/clusters/<name>`** — per-cluster detail with tabs (Nodes,
  Interfaces, Routing, Contact addresses). Full-text **search bar**
  above the tabs supports `AND` / `OR` operators (case-insensitive,
  implicit AND on whitespace), filters every tab in place, highlights
  matching tokens with `<mark.search-hit>`, updates per-tab counts to
  `(M of N)` when filtered.
- **Cluster Forget** — admin button on each engine in the Clusters
  list (only visible when the engine has FlexEdge state). Removes
  every `DhcpEngineCredential` row + the SMC SSH allow rule + uploads
  policy + invalidates cache. Engine itself stays in SMC, reachable
  via SMC Management Client. SMC-side cleanup is attempted FIRST so
  failures don't strand DB state.
- **Terminal icon off-by-one fix** — cluster_detail's
  `creds_by_node.get(n.nodeid)` lookup uses 1-based SMC nodeids; the
  DB stores `node_index` 0-based. The lookup was missing on every
  freshly enrolled node, leaving the terminal icon greyed out. Fixed
  in `_credentials_for_engine`.
- **Cluster detail SMC Element leak fix** — the Routing tab's
  `routing_node_element` field used to leak a live SDK Element object
  past the `with smc_session()` block; Jinja's `str()` cast then
  triggered an API call after the session closed → "No session found"
  500. New `_stringify()` helper materialises every value to a plain
  string at extraction time.

### Added — Platform-wide caching layer (`shared/smc_cache.py`)

`cache_get_or_fetch(section, key_parts, fetcher, ttl, refresh)` —
process-local TTL cache for SMC reads, per-section LRU + TTL,
section names like `engines.list`, `smc.explorer.<type>`, etc.
Default TTL 1 h, hard cap 24 h. Cache key SHA-256s the key parts so
plaintext API keys never end up in the index. Standing rule saved
to memory: every SMC-read view goes through this helper with a
freshness footer + Refresh button. **Reference impl: engines.list**;
rollout to other sections is planned.

### Added — Platform-wide CSRF protection (flask-wtf)

`CSRFProtect(app)` enabled in `webapp/app.py`. Every POST form gets a
`{{ csrf_token() }}` hidden input — patched 26 templates / 40 forms.
Bearer-token webhooks (`tls.api_renew`, `tls.api_check_renewals`)
explicitly exempted. A `<meta name="csrf-token">` in base.html plus a
`window.fexFetch()` wrapper auto-attaches `X-CSRFToken` to AJAX calls.

### Added — SMC global session lock (`shared/smc_lock.py`)

`smc-python` keeps session state in a module-level singleton. Under
gunicorn `-k gthread --threads 8`, two concurrent requests would race
on `session.login` / `session.logout` — symptoms ranged from
intermittent "No session found" errors to domain bleeding between
users. New process-wide re-entrant lock serialises every entry into
`smc_session(...)` (and the ad-hoc `session.login` paths in
admin-portal probes). Throughput drops to "one in-flight SMC op per
worker process" — fine for an admin tool.

### Added — DHCP credentials wizard redesign (status-aware, AJAX)

Full rewrite per the operator's linear-flow spec:

- **Live credential test at discover** — `/credentials/discover-nodes`
  runs a TCP probe + SSH `verify_credential` for every existing cred.
  Each node returns `cred_status ∈ {not_enrolled, working, broken}`.
- **Status-aware per-node UI**: `not_enrolled` → green Auto-enroll
  (rotates pwd); `working` → green badge + blue **Apply** (DB-only
  metadata update, no rotation); `broken` → red badge + reason +
  yellow **Overwrite credential** (rotates pwd).
- **Bulk button** is intent-aware: counts new / verified / broken in
  a confirm dialog, routes each node to the right endpoint
  sequentially. No more "rotate all unenrolled" hammer.
- **Live source-IP drift detection** — discover reads each rule's
  source Host's actual IP from SMC and compares against the tenant's
  current `flexedge_source_ip`. On drift, the Rule card shows the
  live IPs + **Overwrite source** / **Add source** buttons.
- **Single canonical rule per engine** — never duplicate. The
  versioned-name approach was reverted on operator feedback.
  `update_source_host_address(...)` and `add_source_host_to_rule(...)`
  mutate the existing rule's source(s).
- **AJAX everywhere — no page refresh on rule actions.** Install
  rule, Push policy, Overwrite source, Add source all return JSON.
  Page-level submit delegator intercepts these forms; on success,
  auto re-runs Discover (silently) so the wizard repaints with the
  new live state. Wizard selections, scroll position, per-node
  panels are preserved.
- **Card 3 inline refresh** — after any successful enrollment, apply,
  or overwrite, `refreshCard3()` swaps just the Card-3 contents from
  a fresh page fetch — no full reload.
- **Auto-select API key** when the chosen tenant has only one active
  key.
- **`/credentials/apply`** new route — DB-only metadata update for
  working credentials. Pre-flights TCP+auth before committing.
- **`/credentials/policy-install`** new route — force a policy upload
  to an engine without changing the rule (Push policy button on Card 3).

### Added — DHCP credentials cache freshness (`webapp/engine_credentials.py`)

Engines-agnostic helper module:

- `state_refreshed_at` columns on `DhcpEngineCredential` and
  `DhcpEngineSshAccess` (additive migration in db_init).
- `get_engine_freshness(...)` returns a `FreshnessSummary`
  (green/amber/red bands; 24 h hard cap).
- `refresh_engine_state(...)` runs the live probe (SMC rule + per-node
  TCP + SSH verify) and returns a structured `RefreshReport` with
  per-component drift messages. Bumps timestamps on rows that
  verified ok.
- New AJAX route `POST /dhcp/credentials/refresh` returns JSON when
  called via `Accept: application/json`; the per-engine "Refresh
  state" button on Card 3 uses it to update the badge + render an
  inline result panel **without reloading the page**.
- All existing ops (bootstrap, verify, force-reset, rule install,
  Phase 4 deploy) bump `state_refreshed_at` on success.

### Added — Phase 0 validation gate for DHCP Phase 4

DHCP Phase 4 is now blocked at preflight until an operator clicks
"I validated Phase 0" on the dashboard. Validation recorded as a
`DhcpActivityLog` row (category=`system`, action=`phase0_validated`);
revoking deletes the row. Dry-run / Preview path bypasses the gate.

### Added — DHCP Phase 4 dry-run / preview

`preview_scope(scope_id, op)` runs the full SSH read + render + diff
pipeline, persists `DhcpDeployment` rows with `action="dry_run"`, but
skips `put_file` and the dhcpd reload. New page
`templates/dhcp/scope_preview.html` shows per-node sha256 before/after,
the unified diff, plus a final "Looks good — Deploy now" button.

### Added — Migration importer: auto-install policy + transactional safety

- **Auto-install checkbox** in the migration import form — default
  off. When ticked, `Engine(<engine_name>).upload(...)` runs at the
  end of the import. Flash messages and the "Engine activation"
  badge in the Import Summary differentiate four states:
  installed-and-live (green), install-failed (red), install-skipped
  (yellow), or rules-not-yet-live (yellow with NEXT STEP pointer).
- **Orphan-Host rollback** in `migration_dhcp_writer.py` — when a per-
  reservation DB write fails after an SMC `host_create` succeeded,
  the Host is immediately deleted. Outer scope-level failures roll
  back every `created_hosts[]` in a fresh SMC session and surface
  unrecoverable orphans by name.

### Hardening (security + correctness)

- **Source-IP drift banner** also surfaced passively on Card 3
  (yellow per-engine banner with Add / Overwrite buttons).
- **Fingerprint-change audit** — `force_reset_password` recovering
  via TOFU after a host-key mismatch records both old and new
  fingerprints in the audit log + flashes a yellow warning.
- **`DhcpDeployment.reload_warning`** column split from `error`.
- **`host_delete` tri-state** — True (deleted), False (not found,
  idempotent ok), raise (real failure). Both callers updated.
- **MAC marker hardening** — case-insensitive prefix, internal
  whitespace tolerated, multiple markers → last wins + WARN-log
  earlier ones, malformed MAC inside well-formed brackets is stripped.
- **Reservation uniqueness** — `(scope_id, mac_address)` AND
  `(scope_id, ip_address)` UNIQUE constraints.
- **Per-engine push lock** — Phase 4 deploy wraps in `engine_op_lock`.
- **Per-scope block markers** — different scopes on the same engine
  no longer strip each other's reservation blocks.
- **`pkill -HUP -x`** exact-match — never accidentally HUPs an
  editor session.
- **Multi-tenant `smc_url` fallback** — `find_tenant_for_target`
  refuses to guess when multiple tenants share an SMC URL and no
  API-key hash matches; surfaces an actionable warning.

### Added — Log retention sweep + CLI

`sweep_old_logs(retention_days)` deletes `dhcp_activity_logs` and
`dhcp_deployments` older than the cutoff (Phase 0 validation rows
preserved). Admin-only `POST /dhcp/system/sweep-logs` triggers
manually; `cli/sweep_dhcp_logs.py` for cron-based runs.

### Architecture decisions saved to memory

Standing rules now persisted across sessions (in
`~/.claude/projects/.../memory/`):

- **`feedback_logging_standing_rule.md`** — every new feature must
  integrate with the platform audit + op log; per-feature toggle +
  retention configurable from Admin Portal (planned).
- **`feedback_credentials_are_engines_level.md`** — DHCP-namespaced
  `DhcpEngineCredential` / `/dhcp/credentials/*` is legacy naming;
  rename + URL move pending. New code uses
  `webapp/engine_credentials.py`.
- **`feedback_caching_pattern.md`** — every SMC-read view goes
  through `shared/smc_cache.py` with refresh button + freshness
  footer.
- **`project_change_management_plan.md`** + **`docs/ChangeManagementProcess.md`** —
  PLANNED two-phase queue between operator clicks and SMC commits.
  Subsumes ad-hoc push paths (migration writer, TLS deploy, DHCP rule
  install, DHCP Phase 4). 6-8 days total.

## [2.2.0-dev] - 2026-04-25

### Added — FortiGate DHCP migration (phases A, B, C, D landed 2026-04-25)

The FortiGate import now handles `config system dhcp server` blocks
end-to-end and feeds them into the existing DHCP Manager:

- **Phase A** (parser + read-only review tab) — `_extract_dhcp_servers()`
  in fgt_parser, "DHCP" tab on parsed.html with per-scope cards.
  See e184773.
- **Phase B** (target mapping + DHCP-ready guard) — `webapp/dhcp_readiness.py`
  resolves migration target → tenant + lists candidate scopes with
  ready/not-ready tags. New `/migration/<id>/dhcp-map` route + template
  persists `target.dhcp_mappings`. See 412f61d.
- **Phase C** (dedup) — `_dedup_dhcp_reservations()` in dedup_engine.py
  classifies each parsed reservation against existing DhcpReservation
  rows on the mapped target scope (already_migrated / mac_conflict /
  ip_conflict / new). DB-only, no SMC session required. New "DHCP" tab
  on dedup.html with per-FG-scope cards + per-reservation checkboxes
  and a "⚙ Overwrite" button for conflicts (operator opts into making
  the FG value win at import).
- **Phase D** (importer) — `webapp/migration_dhcp_writer.py`
  `import_dhcp_reservations()` calls `smc_dhcp_client.host_create()`
  (same path the DHCP Manager UI uses, same `[flexedge:mac=...]` comment
  marker) for every selected reservation, inserts a DhcpReservation row
  with `source="migration:<project_id>"` and `status="pending"` so it
  appears in the existing DHCP Manager UI ready for the existing Phase 4
  "Deploy" button. **Migration never pushes** — it only stages.
- **Locked design constraints** (chat with operator, 2026-04-25):
  imported config wins in staging (conflicts default off; operator opts
  into overwrite); migration reuses DHCP Manager primitives entirely;
  un-ready scopes are blocked at import with deep links to enroll/enable
  rather than auto-enrolling.
- **Schema additions** (additive, lightweight): `DhcpReservation.source`
  column for traceability ("migration:&lt;project_id&gt;"). Migrated rows
  show a "From migration" source tag in the DHCP Manager UI.

Files: webapp/dhcp_readiness.py, webapp/migration_dhcp_writer.py,
webapp/dedup_engine.py (extended), webapp/db_init.py (ALTER TABLE for
.source), webapp/templates/migration/{dhcp_map,dedup,parsed}.html,
webapp/app.py (new routes: /dhcp-map GET/POST, /dhcp/update AJAX,
/import wired to the writer).

### Added — DHCP Reservation Manager (in progress — phases 0, 1, 1b, 1c, 2, 3, 4 landed)

**Phase 4 — engine-side reservation push (2026-04-25):**

- **`webapp/dhcp_pusher.py`** — new module: renders FlexEdge-managed reservations as ISC dhcpd `host { hardware ethernet ...; fixed-address ...; }` blocks, merges them into `/data/config/base/dhcp-server.conf` between `# FLEXEDGE-RESERVATIONS-BEGIN` / `# FLEXEDGE-RESERVATIONS-END` markers (idempotent: replaces existing block in place), and atomically writes via `put_file()` (tmp + posix_rename). SMC's subnet block is never touched — host blocks at top level work because ISC matches them by IP into the surrounding subnet.
- **Per-node orchestration** — `push_scope_to_engine(scope_id, operator_email, action)` runs against every cluster node in order: TCP probe → credential verify → read current file → render + merge → atomic write → re-read verify (sha256 round-trip) → best-effort `pkill -HUP` reload. Each node gets a `DhcpDeployment` audit row with sha256_before/after, unified diff (trimmed to 200 lines), duration, and any reload warning. Reservation rows flip to `synced` on full success, `error` on partial / total failure (with `last_error` populated).
- **Pre-flight guard** — `_check_preconditions()` blocks the push if the scope isn't `enabled_in_flexedge`, any cluster node lacks a verified credential, or the SSH allow rule is missing — surfacing a clear operator-facing message + `dhcp_activity_logs` row instead of attempting and failing per-node.
- **Wired into existing routes** — `POST /dhcp/scopes/<id>/deploy` and `POST /dhcp/scopes/<id>/resync` now call the pusher (replacing the Phase-3 stubs that only flashed warnings). The existing "Deploy to engine" button on `scope_detail.html` works without template changes.
- **Per-node failure isolation** — failures on one node never abort the loop; aggregate status is `ok` (all nodes), `partial` (some), or `failed` (none). Operator gets per-node detail in flash messages and the deployment-history card.
- **Reload best effort** — `pkill -HUP` against `dhcp-server` then `dhcpd` (Forcepoint engines run the daemon under either name); if neither matches we surface a warning and tell the operator to refresh the policy in SMC. Never fails the deployment over a reload issue.

**Cluster-wide enrollment + summary view (UX iteration, late Apr 2026):**

**Cluster-wide enrollment + summary view (UX iteration, late Apr 2026):**

- **Multi-IP SSH allow rule** — `add_ssh_access_rule(... destination_ips: list)` now creates one rule with N Host elements (`<rule_name>-dst-0`, `<rule_name>-dst-1`, …) so a single rule covers every cluster node. Multi-checkbox picker in the UI; SMC-initiated cluster pre-checks all IPs, node-initiated requires explicit operator selection. Cleanup symmetrically removes both the new `-dst-<n>` shape and the legacy single `-dst` shape.
- **Bulk enrollment** — new `POST /credentials/bootstrap-batch` endpoint enrolls every unenrolled node for an engine within ONE `smc_session` and ONE per-engine lock. Green "Enroll all (N)" button at the top of the cluster nodes section reads each node form's data and submits a single POST. Per-node "Auto-enroll" buttons retained for surgical operations.
- **Dashboard summary** — `/dhcp/` now has a second stats row (Enrolled engines, Total node credentials, Verified, SSH allow rules in policies) and an "Enrolled clusters & nodes" table grouped by (tenant, engine) showing node count, status pills, rule name with multi-IP indicator (`+N more`), and last-verified timestamp.
- **NDI-based node discovery** — `list_cluster_nodes()` now walks `engine.physical_interface` config (instead of the runtime `interface_status` probe that returned empty). Picks up `NodeInterface` and `SingleNodeInterface` entries from physical + VLAN children, groups by `nodeid`. Skips `cluster_virtual_interface` (CVI) — those are shared cluster IPs, not per-node targets.
- **Node-initiated contact detection** — new `is_node_initiated_contact()` reads the `reverse_connection` flag on every primary mgmt interface (the SDK's name for what the SMC GUI calls "Node-Initiated Contact"). Banner in the rule install card; per-node IP picker requires explicit selection vs auto-suggesting the primary mgt IP.

- **Phase 1c — Auto-enrollment via SMC API**. Replaces the Phase 1 password-prompt flow.
  - **No password ever typed by the operator.** FlexEdgeAdmin generates a 64-char random root password and sets it via SMC's `node.change_ssh_pwd` endpoint.
  - **No public-key install.** Auth is **password-only** (Fernet-encrypted in DB, pinned host fingerprint), engine `authorized_keys` left untouched.
  - **SSH allow rule** auto-installed on the engine's active policy (name `flexedge-dhcp-mgmt-ssh-<engine>`), with operator-confirmed source IP. Rule is removed when last credential for the engine is deleted, or via a manual "Remove SSH rule" button. Detected if removed externally — banner asks operator to recreate.
  - **Per-engine concurrency lock** prevents two enrollments racing on the same node's password.
  - **A3 recovery path**: when verify fails with `paramiko.AuthenticationException` (someone changed root pw out of band), an operator-confirmed "Force re-bootstrap" button rotates the password again via SMC API.
  - **Pre-flight TCP probe** to the chosen node IP before mutating anything — fails fast with a clear error if the rule push didn't open the path.
  - **Public-IP probe** (api.ipify.org / ifconfig.me / icanhazip) suggests the FEA source IP per tenant; operator confirms or overrides.
- **Schema changes (auto-migrating on boot)**:
  - `tenants.flexedge_source_ip` (new column, ALTER TABLE on existing DBs).
  - `dhcp_engine_credentials` — replaces `public_key_openssh` + `private_key_pem` with `encrypted_password`. Existing key-based rows from earlier dev-only Phase 1 are dropped on first boot of the new schema (logged warning); re-enroll affected nodes.
  - `dhcp_engine_ssh_access` (new) — tracks the FlexEdge-managed SSH allow rule per engine with the rule name as the stable lookup tag.
- **CLAUDE.md DB schema section** to be updated in Phase 6 along with all docs.

### Phase summary (cumulative across earlier 2.2.0-dev iterations)

- **Phase 0** — [docs/DHCP-Phase0-LabTest.md](docs/DHCP-Phase0-LabTest.md): operator-ready procedure to verify whether `/data/config/base/dhcp-server.conf` survives policy refresh/upload/reboot. Gates Phase 4.
- **Phase 2** — DB tables `dhcp_scopes`, `dhcp_reservations`, `dhcp_deployments`, `dhcp_activity_logs`, `dhcp_engine_credentials`, `dhcp_engine_ssh_access`.
- **Phase 3** — DHCP Manager Blueprint at `/dhcp/*` (admin-only): scope discovery (recursive walker handling multiple DHCP-config shapes), reservation CRUD with `[flexedge:mac=...]` marker on SMC Host comment, sync-from-SMC, deploy stub, diagnostic endpoint, activity log.
- **Phase 1b** — Cluster lease viewer: ISC `dhcpd.leases` parser, per-engine cluster lease table with reservation cross-check (mismatch flagged red).

### Changed — DHCP Reservation Manager

- `webapp/models.py` docstring updated to list the new DHCP tables.
- Sidebar nav gained a "DHCP Manager" section (admin-only).
- `docs/DHCP-ResrvationStrategy.md` → `docs/DHCP-ReservationStrategy.md` (filename typo fix via `git mv`).

## [2.1.0] - 2026-04-15

### Added

- **TLS Manager** — new admin-only feature (`/tls/*`) that automates TLS certificate lifecycle for Forcepoint NGFW engines, bridging Let's Encrypt (certbot) with the SMC API:
  - Track certbot-managed certificates (reads `/etc/letsencrypt/live/`)
  - Deploy pipeline: import cert as `TLSServerCredential`, create host objects, assign to engine TLS inspection, create access rule with deep inspection + file filtering + decryption, upload policy
  - Reuses existing `Tenant` + `ApiKey` models — no duplicate SMC connection config
  - Renewal webhook (`POST /tls/api/renew`, Bearer-token auth) callable by certbot's deploy-hook
  - In-app deploy-hook generator + auto-installer (writes to `/etc/letsencrypt/renewal-hooks/deploy/`)
  - Activity log on dashboard: every operation, full error details, filterable by status
  - Supports domain-scoped API keys (keys that can't enumerate admin domains use their API client name as a domain hint)
- **Certbot in the main Docker image** — `apt install certbot` added to `docker/Dockerfile`
- **`/etc/letsencrypt` volume mount** added to `docker/docker-compose.yml` (read-only)
- **New DB tables** (auto-created on first boot): `managed_certificates`, `tls_deployments`, `tls_deployment_logs`, `tls_activity_logs`
- **Documentation**: TLS Manager feature documented inline in `CLAUDE.md` (developer reference) and `docs/deployment-guide.md` (operator setup + troubleshooting) — same treatment as Admin Portal and Migration Manager

### Changed

- Sidebar nav now includes a "TLS Manager" section (admin-only)
- `CLAUDE.md` updated with the TLS Manager feature description and DB schema additions

### Fixed

- **Engine discovery in TLS Manager** now covers all SMC engine types via a three-stage cascade: (1) generic `Engine.objects.all()`, (2) per-subclass enumeration (Layer 2 / cluster / virtual / master / IPS / cloud), (3) **raw REST fallback** against `/elements/engine_clusters` and every specific-type endpoint. Each engine gets a list of which stages saw it, exposed via the new diagnostic endpoint. Previously only `Layer3Firewall` and `FirewallCluster` were queried.
- **Deploy.sh path with spaces** — the script now uses relative compose paths with an upfront `cd "$PROJECT_DIR"`, fixing the "unknown docker command" word-splitting bug when the project lives under a folder with spaces (e.g. iCloud Drive).

### Added — developer/operator visibility

- **Running build version in the web UI** — sidebar footer now shows `v{version} ({commit})` with a tooltip containing the full commit SHA and ISO build date. Click the version to open the `/version` JSON endpoint.
- **New `/version` endpoint** — returns `{version, commit, commit_full, build_date, display}` as JSON. Unauthenticated, safe for monitoring / uptime checks.
- **Version metadata injection** — `deploy.sh` auto-computes `FLEXEDGE_VERSION` (from CHANGELOG.md top entry), `FLEXEDGE_COMMIT` (short git SHA), `FLEXEDGE_COMMIT_FULL`, `FLEXEDGE_BUILD_DATE` (UTC ISO-8601) before `docker compose build` and passes them as build args. Dockerfile accepts the args and bakes them into `ENV`. `shared/version.py` reads env vars first, falls back to a committed `.version.json` file (stamped by `pack-release.sh`), then to live `git` commands, and finally to CHANGELOG parsing for the version string.
- **Coolify-compatible version stamping** — `scripts/pack-release.sh` writes a `.version.json` file into `FlexEdgeAdminProd/` on every release, containing `version`, `commit`, `commit_full`, and `build_date`. The Dockerfile copies it into the image via a glob wildcard (`COPY .version.jso[n] ./` — silent when the file is absent in the private repo). Coolify customers building directly from the public repo get the correct version displayed in the UI without any Coolify-side configuration.
- **Customer deployment verification** — `pack-release.sh --verify <URL>` polls `<URL>/version` every 5 seconds after pushing until the customer's running build matches the pushed commit. Repeatable (pass `--verify` multiple times for several customers), with a configurable `--verify-timeout` (default 30 seconds). Prints per-customer OK / FAIL summary at the end. Useful for confirming Coolify redeploys landed.
- **TLS engine-fetch activity logging** — every `/api/tenants/<id>/api-keys/<id>/engines` call now writes an entry to `tls_activity_logs` with the returned engine list, so you can see from the dashboard what the API returned without re-opening the browser inspector.
- **New TLS diagnostic endpoint** `/tls/api/tenants/<tid>/api-keys/<kid>/engines/debug` — returns the full engine list with per-source attribution (which discovery stage saw each engine), used for troubleshooting missing-engine cases.

### Removed

- Standalone `FlexEdgeTLSManagement/` folder and its `.gitignore` entry (merged into the main webapp as a Blueprint)

### Changed — developer ergonomics

- `deploy.sh --dev` — new explicit dev flag that runs the guided bootstrap (Docker check, `.env` setup, Azure AD prompt), then `docker compose up --build` in the **foreground** with live logs (Ctrl+C to stop)
- `make dev` now routes through `./deploy.sh --dev` so first-time setup works without manually creating `.env`. Previously it failed if `.env` was missing.
- `make prod` now routes through `./deploy.sh` (production with TLS)
- `make dev-raw` / `make prod-raw` — new escape hatches for the raw `docker compose` commands (CI, debugging) that skip the bootstrap
- `--no-tls` kept as a detached (background) dev mode for CI/automation

## [2.0.0] - 2026-04-12

### Added

- **Three deployment options** documented and supported:
  - **Standalone**: new `scripts/install-standalone.sh` — native install with
    Python venv at `/opt/flexedge/`, config at `/etc/flexedge/`, systemd service
    (`flexedge.service`), nginx site config, certbot-ready
  - **Docker + nginx**: unchanged `./deploy.sh` flow (full stack via compose)
  - **Coolify / Traefik**: new `docker/docker-compose.coolify.yml` — no bundled
    nginx/certbot (Coolify handles TLS, routing, Let's Encrypt via Traefik)
  - Full 3-option comparison table and per-option instructions in
    `docs/deployment-guide.md`
- **Uninstall support** in `deploy.sh`:
  - `--uninstall` — stop/remove containers, preserve all data and config
  - `--uninstall --purge` — full clean slate: deletes DB, encryption key, .env,
    Docker images, certbot volumes (requires typing "PURGE" to confirm)
- **Azure setup automation** (`scripts/azure-setup.sh`) — single command to:
  - Create Entra ID App Registration with OIDC configuration
  - Enable ID tokens, set redirect URIs (dev + production)
  - Create client secret (2-year expiry)
  - Add Microsoft Graph permissions (openid, email, profile)
  - Grant admin consent
  - Generate Flask secret key
  - Write complete `.env` file
  - Flags: `--domain`, `--app-name`, `--skip-consent`
  - Integrated into `deploy.sh` (offers to run automatically)
- **Admin Portal** (`/admin/`) — web-based CRUD for tenants, users, and API keys
  - Tenant management: create, edit, soft-delete SMC server connections
  - User management: create, edit, role assignment (admin/viewer), tenant access mapping
  - API Key management: Fernet-encrypted storage, one-time plaintext display on creation, revoke
  - Backup: download ZIP of database + encryption key from Admin Portal
  - JSON Migration: one-click import from legacy `tenants.json` + `users.json`
  - Admin dashboard with stats, backup, and migration controls
- **Encrypted database** — SQLite with Fernet field-level encryption (AES-128-CBC + HMAC-SHA256)
  - Binary encryption key file (`FXEK` magic header format) auto-generated on first run
  - Without the key file, encrypted API keys are permanently irrecoverable (by design)
  - SQLite WAL mode enabled for concurrent read performance
  - Database schema: `tenants`, `users`, `api_keys`, `user_tenant_access` tables
- **Setup wizard** — one-time `/setup` page on first run
  - Requires Azure AD login first (security: only valid Azure AD users can claim admin)
  - Creates the first admin user, then becomes permanently inaccessible
- **DB-backed data layer** — user profiles and tenant config read from DB with JSON fallback
  - `webapp/user_manager.py` queries DB first, falls back to `users.json`
  - `shared/tenant_config.py` queries DB first, falls back to `tenants.json`
  - CLI tools automatically use JSON fallback (no Flask context needed)
- **New files**: `webapp/admin.py`, `webapp/setup.py`, `webapp/models.py`, `webapp/db_init.py`,
  `shared/encryption.py`, `shared/db.py`, 10 admin templates

### Changed

- **Configuration model** — JSON files replaced by Admin Portal as primary config method
  - `.env` is the only file to edit before first start (Azure AD credentials)
  - Tenants, users, and API keys managed via web UI instead of JSON files
- **Docker volumes** — `config/` directory mounted as a whole (contains DB + key + legacy JSONs)
- **deploy.sh** — no longer creates `tenants.json` / `users.json`; points users to setup wizard
- **requirements.txt** — added `flask-sqlalchemy>=3.1`, `cryptography>=42.0`
- **`.gitignore`** — added `*.db`, `encryption.key`
- **Sidebar** — admin link visible only to admin-role users
- **`scripts/pack-release.sh`** — production release packer
  - Builds a clean `./production/` folder with zero client-specific data
  - Sanitizes firewall names, IP ranges, server URLs, client references
  - Automated verification scan — aborts on any leaked secrets
  - `--no-push` flag to skip pushing (default: commit and push)
  - `--message "msg"` for custom commit messages
  - Preserves `production/.git` across rebuilds (remote config, history retained)

### Security

- Removed `__pycache__/connect.cpython-314.pyc` from git tracking
- Sanitized `scripts/service_mapping.json` (replaced real SMC URL with placeholder)
- Sanitized `config/smc_config.yml.example` (removed client name)
- `production/` folder gitignored — clean public release with no git history leak

---

## [1.0.0] - 2026-04-12

### Added

- **FlexEdgeAdmin branding** — unified project identity replacing "SMC Explorer"
- **Shared tenant configuration** (`shared/tenant_config.py`) — single source of truth
  for SMC connection definitions, used by both CLI and webapp
  - `config/tenants.json` defines URL, SSL, timeout, domain per tenant
  - API keys remain per-user (in `users.json` for web, env var for CLI)
- **Unified Docker setup** — single image containing webapp + CLI + migration scripts
  - `docker/Dockerfile` — python:3.12-slim with gunicorn
  - `docker/docker-compose.yml` — development compose
  - `docker/docker-compose.prod.yml` — production overlay with nginx + certbot TLS
  - `docker/nginx.conf` — reverse proxy with security headers
- **Deployment automation**
  - `deploy.sh` — one-command VPS setup (installs Docker, creates configs, starts services)
  - `Makefile` — convenience targets (dev, prod, stop, logs, cli, update)
  - `docs/deployment-guide.md` — complete operator guide
- **Configuration templates** — `.example` files for all secrets
  - `config/tenants.json.example`, `config/users.json.example`
  - `config/.env.example`, `config/config.ini.example`
- **APP_TITLE env var** — customizable branding per deployment

### Changed

- **Repository restructured** into `cli/`, `webapp/`, `shared/`, `scripts/`, `config/`, `docker/`, `docs/`
- **CLI connect.py** — now supports `--tenant` flag + `SMC_API_KEY` env var; falls back to legacy `config.ini`
- **CLI smc.sh** — passes `--tenant` flag, sets PYTHONPATH, venv at project root
- **webapp/user_manager.py** — resolves tenant references from `tenants.json`; backward compatible with old embedded `smc_url` format
- **users.json format** — profiles now reference tenants by ID instead of embedding full connection details
- Unified `requirements.txt` at project root (merged CLI + webapp deps)

### Security

- Removed `config.ini` from git tracking (contained real API key)
- All secret files added to `.gitignore`: `config.ini`, `tenants.json`, `users.json`, `.env`, `smc_config.yml`
- Docker never bakes secrets into images — always volume-mounted

---

## [0.3.0] - 2026-04-11

### Added

- **Microsoft Entra ID OIDC login** — all webapp routes protected
- **Multi-user support** — per-user SMC API profiles via `users.json`
- **SMC admin domain selection** per session
- **ProxyFix** for correct HTTPS redirect URIs behind reverse proxies

---

## [0.2.0] - 2026-03-11

### Added

- **SMC Explorer webapp** — read-only browser for all SMC objects and policies
- **Migration Manager** — 7-step guided FortiGate-to-Forcepoint migration workflow
- **NAT rules migration** — SNAT dynamic, DNAT static, combined
- **IPsec VPN migration** — profiles, gateways, sites, PolicyVPN
- **Docker deployment** — Dockerfile, docker-compose.yml

---

## [0.1.0] - 2026-01-20

### Added

- Initial CLI tools: `connect.py`, `inquiry.py`, `firewall.py`, `smc.sh`
- Firewall management: list, show, interfaces, add/delete/update interface, VLAN, policy refresh/upload
- Object query and inspection with type/name filtering
- Cluster support: CVI, NDI, multi-node configuration
- Documentation: guides for each CLI module
