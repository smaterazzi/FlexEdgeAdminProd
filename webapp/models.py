"""
FlexEdgeAdmin — SQLAlchemy models.

Tables:
  tenants             SMC server connections
  users               Authenticated users (from Azure AD)
  api_keys            Encrypted SMC API keys
  user_tenant_access  Junction: which users can access which tenants with which keys
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


def enable_wal_mode(app):
    """Enable WAL mode for SQLite after db.init_app(). Call from app setup."""
    with app.app_context():
        if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
            with db.engine.connect() as conn:
                conn.execute(db.text("PRAGMA journal_mode=WAL"))
                conn.commit()
