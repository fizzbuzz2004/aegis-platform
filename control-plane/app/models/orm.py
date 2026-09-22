from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    # BUGFIX: Syntax-Fehler 'primary_primary=True' wurde korrigiert
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    enrollment_code = Column(String(128), unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    hosts = relationship("HostDevice", back_populates="tenant", cascade="all, delete-orphan")
    modules = relationship("TenantModule", back_populates="tenant", cascade="all, delete-orphan")
    results = relationship("ModuleResult", back_populates="tenant", cascade="all, delete-orphan")

class HostDevice(Base):
    __tablename__ = "host_devices"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    hostname = Column(String(100), nullable=False)
    os_info = Column(String(100), nullable=False)
    host_token = Column(String(255), unique=True, index=True, nullable=False)
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
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    hostname = Column(String(100), nullable=False)
    module_name = Column(String(50), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    findings = Column(Text, nullable=False)

    tenant = relationship("Tenant", back_populates="results")
