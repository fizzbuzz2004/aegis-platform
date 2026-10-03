from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class V2Base(DeclarativeBase):
    pass


class MSP(V2Base):
    __tablename__ = "msps"
    __table_args__ = {"schema": "aegis_v2"}

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)


class Customer(V2Base):
    __tablename__ = "customers"
    __table_args__ = (
        UniqueConstraint("msp_id", "customer_id"),
        {"schema": "aegis_v2"},
    )

    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("aegis_v2.msps.id"), primary_key=True)
    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PrincipalMembership(V2Base):
    __tablename__ = "principal_memberships"
    __table_args__ = (
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        Index(
            "principal_memberships_msp_scope_uq",
            "principal_id",
            "msp_id",
            unique=True,
            postgresql_where=text("customer_id IS NULL"),
        ),
        Index(
            "principal_memberships_customer_scope_uq",
            "principal_id",
            "msp_id",
            "customer_id",
            unique=True,
            postgresql_where=text("customer_id IS NOT NULL"),
        ),
        CheckConstraint("role IN ('MSP_ADMIN', 'TECHNICIAN', 'CUSTOMER_ADMIN', 'AGENT')"),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    principal_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("aegis_v2.msps.id"), nullable=False)
    customer_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScanRun(V2Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        UniqueConstraint("msp_id", "customer_id", "id"),
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        CheckConstraint("status IN ('queued', 'running', 'complete', 'failed')"),
        Index("scan_runs_tenant_time", "msp_id", "customer_id", "started_at"),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    data_as_of: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rule_pack_id: Mapped[str] = mapped_column(Text, nullable=False)
    rule_pack_digest: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)


class ScanFinding(V2Base):
    __tablename__ = "scan_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        ForeignKeyConstraint(
            ["msp_id", "customer_id", "scan_run_id"],
            ["aegis_v2.scan_runs.msp_id", "aegis_v2.scan_runs.customer_id", "aegis_v2.scan_runs.id"],
        ),
        Index("scan_findings_scan_idx", "msp_id", "customer_id", "scan_run_id"),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    scan_run_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EvidenceChainHead(V2Base):
    __tablename__ = "evidence_chain_heads"
    __table_args__ = (
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        CheckConstraint("octet_length(head_hash) = 32"),
        {"schema": "aegis_v2"},
    )

    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    sequence_number: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    head_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EvidenceEvent(V2Base):
    __tablename__ = "evidence_events"
    __table_args__ = (
        UniqueConstraint("msp_id", "customer_id", "sequence_number"),
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        CheckConstraint("octet_length(previous_hash) = 32"),
        CheckConstraint("octet_length(event_hash) = 32"),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    sequence_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    previous_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    event_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    canonical_event: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    pseudonymous_subject: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class EvidenceAnchorManifest(V2Base):
    __tablename__ = "evidence_anchor_manifests"
    __table_args__ = (
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        CheckConstraint("first_sequence > 0 AND last_sequence >= first_sequence"),
        CheckConstraint("octet_length(merkle_root) = 32"),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    first_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    merkle_root: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kms_key_arn: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    object_key: Mapped[str] = mapped_column(Text, nullable=False)
    anchored_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ReportJob(V2Base):
    __tablename__ = "report_jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        ForeignKeyConstraint(
            ["msp_id", "customer_id", "snapshot_id"],
            ["aegis_v2.scan_runs.msp_id", "aegis_v2.scan_runs.customer_id", "aegis_v2.scan_runs.id"],
        ),
        CheckConstraint("status IN ('queued', 'running', 'complete', 'failed')"),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    requested_by: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    snapshot_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    data_as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rule_pack_digest: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    object_key: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OutboxEvent(V2Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["msp_id", "customer_id"],
            ["aegis_v2.customers.msp_id", "aegis_v2.customers.id"],
        ),
        Index(
            "outbox_unpublished_idx",
            "available_at",
            "created_at",
            postgresql_where=text("published_at IS NULL"),
        ),
        {"schema": "aegis_v2"},
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    msp_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    customer_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
