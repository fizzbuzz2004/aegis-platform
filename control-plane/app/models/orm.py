from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

# Korrigierter Import (ohne das ungültige 'control-plane')
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_primary=True, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    api_token = Column(String(128), unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    modules = relationship("TenantModule", back_populates="tenant", cascade="all, delete-orphan")
    results = relationship("ModuleResult", back_populates="tenant", cascade="all, delete-orphan")

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
