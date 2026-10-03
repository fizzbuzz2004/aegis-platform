import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON, Enum
from sqlalchemy.orm import relationship
from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    JUNIOR = "JUNIOR"
    TECHNICIAN = "TECHNICIAN"
    CUSTOMER_ADMIN = "CUSTOMER_ADMIN"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.TECHNICIAN, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    mfa_secret = Column(String(32), nullable=True)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True)
    must_change_password = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    parent_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    hierarchy_path = Column(String(255), index=True, nullable=False, default="/")

    name = Column(String(100), nullable=False)
    enrollment_code = Column(String(128), unique=True, index=True, nullable=False)
    logo_base64 = Column(Text, nullable=True)
    brand_color_hex = Column(String(7), nullable=False, default="#0f766e")
    custom_footer = Column(String(500), nullable=True)
    psa_company_id = Column(String(100), nullable=True)
    psa_site_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    parent = relationship("Tenant", remote_side=[id], backref="children")
    hosts = relationship("HostDevice", back_populates="tenant", cascade="all, delete-orphan")
    modules = relationship("TenantModule", back_populates="tenant", cascade="all, delete-orphan")
    results = relationship("ModuleResult", back_populates="tenant", cascade="all, delete-orphan")
    webhooks = relationship("WebhookConfig", back_populates="tenant", cascade="all, delete-orphan")


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    url = Column(String(255), nullable=False)
    secret_token = Column(String(255), nullable=False)
    provider = Column(String(30), nullable=False, default="generic")
    auth_header = Column(String(100), nullable=True)
    auth_value = Column(String(512), nullable=True)
    events = Column(String(255), default="ALL")
    is_active = Column(Boolean, default=True)

    tenant = relationship("Tenant", back_populates="webhooks")


class HostDevice(Base):
    __tablename__ = "host_devices"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    hostname = Column(String(100), nullable=False)
    os_info = Column(String(100), nullable=False)
    host_token = Column(String(255), unique=True, index=True, nullable=False)
    client_cert_fingerprint = Column(String(64), nullable=True, unique=True, index=True)
    is_active = Column(Boolean, default=True, server_default="true", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant", back_populates="hosts")


class TenantModule(Base):
    __tablename__ = "tenant_modules"

    tenant_id = Column(Integer, ForeignKey("tenants.id"), primary_key=True)
    module_name = Column(String(50), primary_key=True)
    is_enabled = Column(Boolean, default=False, nullable=False)

    tenant = relationship("Tenant", back_populates="modules")


class ModuleResult(Base):
    __tablename__ = "module_results"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    module_name = Column(String(50), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    findings = Column(Text, nullable=False)
    audit_meta = Column(JSON, nullable=True)

    tenant = relationship("Tenant", back_populates="results")


class PSAAlertState(Base):
    __tablename__ = "psa_alert_states"

    tenant_id = Column(Integer, ForeignKey("tenants.id"), primary_key=True)
    hostname = Column(String(100), primary_key=True)
    module_name = Column(String(50), primary_key=True)
    failing_since = Column(DateTime(timezone=True), nullable=True)
    ticket_created_at = Column(DateTime(timezone=True), nullable=True)
