"""
FlexEdgeAdmin — SQLAlchemy models.

Tables:
  tenants              SMC server connections
  users                Authenticated users (from Azure AD)
  api_keys             Encrypted SMC API keys
  user_tenant_access   Junction: which users can access which tenants with which keys

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
    user_accesses = db.relationship("UserTenantAccess", back_populates="tenant", lazy="dynamic")

    def __repr__(self):
        return f"<Tenant {self.slug!r}>"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(255), default="", nullable=False)
    role = db.Column(db.String(32), default="viewer", nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    # Relationships
    tenant_accesses = db.relationship("UserTenantAccess", back_populates="user", lazy="joined")
    created_api_keys = db.relationship("ApiKey", back_populates="created_by", lazy="dynamic")

    def __repr__(self):
        return f"<User {self.email!r}>"


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    encrypted_key = db.Column(EncryptedString, nullable=False)
    key_hash = db.Column(db.String(64), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    tenant = db.relationship("Tenant", back_populates="api_keys")
    created_by = db.relationship("User", back_populates="created_api_keys")
    user_accesses = db.relationship("UserTenantAccess", back_populates="api_key", lazy="dynamic")

    def set_key(self, plaintext: str):
        """Set the API key plaintext. Encrypts and hashes automatically."""
        self.encrypted_key = plaintext  # EncryptedString handles encryption
        self.key_hash = hash_value(plaintext)

    @property
    def decrypted_key(self) -> str:
        """Read the decrypted API key."""
        return self.encrypted_key  # EncryptedString handles decryption

    def __repr__(self):
        return f"<ApiKey {self.name!r} tenant={self.tenant_id}>"


class UserTenantAccess(db.Model):
    __tablename__ = "user_tenant_access"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "tenant_id", "api_key_id", name="uq_user_tenant_key"),
    )

    # Relationships
    user = db.relationship("User", back_populates="tenant_accesses")
    tenant = db.relationship("Tenant", back_populates="user_accesses")
    api_key = db.relationship("ApiKey", back_populates="user_accesses")

    def __repr__(self):
        return f"<UserTenantAccess user={self.user_id} tenant={self.tenant_id}>"


class ManagedCertificate(db.Model):
    """A certbot-managed certificate tracked for TLS deployment automation."""
    __tablename__ = "managed_certificates"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(512), unique=True, nullable=False, index=True)
    certbot_lineage = db.Column(db.String(1024), nullable=False)
    last_cert_hash = db.Column(db.String(64), default="", nullable=False)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)

    deployments = db.relationship("TLSDeployment", back_populates="certificate",
                                  lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ManagedCertificate {self.domain!r}>"


class TLSDeployment(db.Model):
    """Deployment of a managed certificate to a specific Forcepoint engine."""
    __tablename__ = "tls_deployments"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("managed_certificates.id", ondelete="CASCADE"), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)

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
    tenant = db.relationship("Tenant")
    api_key = db.relationship("ApiKey")
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


class TLSActivityLog(db.Model):
    """Application-wide activity log for TLS operations."""
    __tablename__ = "tls_activity_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category = db.Column(db.String(32), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False)
    target = db.Column(db.String(256), default="", nullable=False)
    detail = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)


# ── DHCP Manager models ─────────────────────────────────────────────────

class DhcpScope(db.Model):
    """A DHCP subnet managed on a specific engine interface.

    Discovered from SMC (one row per engine interface that has the internal
    DHCP server enabled). An operator opts a scope into FlexEdge management
    via `enabled_in_flexedge` before reservations can be deployed.
    """
    __tablename__ = "dhcp_scopes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)

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
        db.UniqueConstraint("tenant_id", "engine_name", "interface_id", name="uq_dhcp_scope_engine_if"),
    )

    tenant = db.relationship("Tenant")
    api_key = db.relationship("ApiKey")
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

    status = db.Column(db.String(32), default="pending", nullable=False)  # pending|synced|out_of_sync|error
    last_synced_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, default="", nullable=False)
    # Origin of this row — empty for manually-added, "migration:<project_id>"
    # for FortiGate-import-generated rows. Used for the "From migration"
    # badge in the DHCP Manager UI and for traceability.
    source = db.Column(db.String(64), default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("scope_id", "mac_address", name="uq_dhcp_res_scope_mac"),
        db.UniqueConstraint("scope_id", "ip_address", name="uq_dhcp_res_scope_ip"),
    )

    scope = db.relationship("DhcpScope", back_populates="reservations")

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
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)

    engine_name = db.Column(db.String(256), nullable=False)
    node_index = db.Column(db.Integer, default=0, nullable=False)
    node_id = db.Column(db.String(128), default="", nullable=False)
    node_name = db.Column(db.String(256), default="", nullable=False)

    hostname = db.Column(db.String(256), nullable=False)       # routable IP or DNS
    ssh_port = db.Column(db.Integer, default=22, nullable=False)
    ssh_username = db.Column(db.String(64), default="root", nullable=False)

    encrypted_password = db.Column(EncryptedString, nullable=False)
    host_fingerprint = db.Column(db.String(128), default="", nullable=False)

    last_verified_at = db.Column(db.DateTime, nullable=True)
    last_verify_status = db.Column(db.String(32), default="unverified", nullable=False)  # ok|failed|unverified
    last_error = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "engine_name", "node_id", name="uq_dhcp_cred_engine_node"),
    )

    tenant = db.relationship("Tenant")
    api_key = db.relationship("ApiKey")

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
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    api_key_id = db.Column(db.Integer, db.ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)

    engine_name = db.Column(db.String(256), nullable=False)
    policy_name = db.Column(db.String(256), default="", nullable=False)
    rule_name = db.Column(db.String(256), nullable=False)        # the tag — stable id
    rule_href = db.Column(db.String(512), default="", nullable=False)  # cached
    fea_source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), default="", nullable=False)  # IP we put in the rule (informational)

    created_by_email = db.Column(db.String(255), default="", nullable=False)
    last_seen_in_policy_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "engine_name", name="uq_dhcp_ssh_access_engine"),
    )

    tenant = db.relationship("Tenant")
    api_key = db.relationship("ApiKey")

    def __repr__(self):
        return f"<DhcpEngineSshAccess {self.engine_name} rule={self.rule_name!r}>"


class DhcpActivityLog(db.Model):
    """App-wide activity log for all DHCP Manager operations."""
    __tablename__ = "dhcp_activity_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category = db.Column(db.String(32), nullable=False)          # scope|reservation|ssh|deploy|system
    action = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False)            # ok|failed|info
    target = db.Column(db.String(256), default="", nullable=False)
    detail = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)


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
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    policy_name = db.Column(db.String(255), nullable=False)

    submitted_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    submitted_at = db.Column(db.DateTime, default=_utcnow, nullable=False, index=True)

    findings_json = db.Column(db.Text, nullable=False)
    finding_count = db.Column(db.Integer, default=0, nullable=False)

    status = db.Column(db.String(20), default="pending", nullable=False, index=True)  # pending|reviewed|closed
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    admin_notes = db.Column(db.Text, default="", nullable=False)

    tenant = db.relationship("Tenant")
    submitted_by = db.relationship("User", foreign_keys=[submitted_by_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])

    def __repr__(self):
        return f"<OptimizationSubmission #{self.id} policy={self.policy_name!r} status={self.status}>"


def enable_wal_mode(app):
    """Enable WAL mode for SQLite after db.init_app(). Call from app setup."""
    with app.app_context():
        if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
            with db.engine.connect() as conn:
                conn.execute(db.text("PRAGMA journal_mode=WAL"))
                conn.commit()
