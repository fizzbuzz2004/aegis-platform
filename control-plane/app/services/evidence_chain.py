from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence
from uuid import UUID, uuid4

import rfc8785
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.v2 import EvidenceAnchorManifest, EvidenceChainHead, EvidenceEvent
from app.core.v2_database import VerifiedTenantContext

ZERO_HASH = bytes(32)
MAX_ANCHOR_BATCH_SIZE = 10_000
ALLOWED_EVIDENCE_FIELDS = frozenset({
    "event_type",
    "asset_ref",
    "rule_id",
    "finding_status",
    "severity",
    "evidence_digest",
    "agent_version",
    "occurred_at",
})


@dataclass(frozen=True)
class AppendedEvidence:
    event_id: UUID
    sequence_number: int
    previous_hash: bytes
    event_hash: bytes


def canonicalize_event(event: Mapping[str, Any]) -> bytes:
    if not isinstance(event, Mapping):
        raise TypeError("evidence event must be a JSON object")
    return rfc8785.dumps(dict(event))


def calculate_event_hash(previous_hash: bytes, canonical_event: bytes) -> bytes:
    if len(previous_hash) != hashlib.sha256().digest_size:
        raise ValueError("previous hash must be a SHA-256 digest")
    return hashlib.sha256(previous_hash + canonical_event).digest()


def verify_evidence_chain_events(events: Sequence[EvidenceEvent]) -> bool:
    previous_hash = ZERO_HASH
    expected_sequence = 1
    for event in events:
        if event.sequence_number != expected_sequence or event.previous_hash != previous_hash:
            return False
        try:
            decoded_event = json.loads(event.canonical_event)
            if canonicalize_event(decoded_event) != event.canonical_event:
                return False
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        calculated_hash = calculate_event_hash(previous_hash, event.canonical_event)
        if not hmac.compare_digest(calculated_hash, event.event_hash):
            return False
        previous_hash = event.event_hash
        expected_sequence += 1
    return True


def pseudonymize_subject(tenant_key: bytes, subject_identifier: str) -> str:
    if len(tenant_key) < 32:
        raise ValueError("tenant pseudonymization key must contain at least 256 bits")
    if not subject_identifier:
        raise ValueError("subject identifier must not be empty")
    digest = hmac.new(tenant_key, subject_identifier.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def calculate_merkle_root(event_hashes: Sequence[bytes]) -> bytes:
    if not event_hashes:
        raise ValueError("cannot anchor an empty evidence batch")
    if any(len(event_hash) != hashlib.sha256().digest_size for event_hash in event_hashes):
        raise ValueError("all event hashes must be SHA-256 digests")
    level = list(event_hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0]


async def _assert_session_scope(session: AsyncSession, context: VerifiedTenantContext) -> None:
    if not session.in_transaction():
        raise RuntimeError("evidence writes require an active tenant transaction")
    result = await session.execute(
        text(
            "SELECT current_setting('app.user_id', true), "
            "current_setting('app.msp_id', true), "
            "current_setting('app.customer_id', true)"
        )
    )
    current_user_id, current_msp_id, current_customer_id = result.one()
    if current_user_id != str(context.user_id) or current_msp_id != str(context.msp_id):
        raise PermissionError("database transaction tenant context does not match evidence scope")
    if current_customer_id != (str(context.customer_id) if context.customer_id else ""):
        raise PermissionError("database transaction customer context does not match evidence scope")
    if context.customer_id is None:
        raise PermissionError("evidence events require a customer-scoped context")


async def append_evidence_event(
    session: AsyncSession,
    context: VerifiedTenantContext,
    event: Mapping[str, Any],
    tenant_pseudonym_key: bytes,
    subject_identifier: str,
) -> AppendedEvidence:
    await _assert_session_scope(session, context)
    unexpected_fields = set(event) - ALLOWED_EVIDENCE_FIELDS
    if unexpected_fields:
        raise ValueError("evidence event contains fields outside the minimized schema")
    pseudonymous_subject = pseudonymize_subject(tenant_pseudonym_key, subject_identifier)

    await session.execute(
        insert(EvidenceChainHead)
        .values(
            msp_id=context.msp_id,
            customer_id=context.customer_id,
            sequence_number=0,
            head_hash=ZERO_HASH,
        )
        .on_conflict_do_nothing(index_elements=["msp_id", "customer_id"])
    )
    head = await session.scalar(
        select(EvidenceChainHead)
        .where(
            EvidenceChainHead.msp_id == context.msp_id,
            EvidenceChainHead.customer_id == context.customer_id,
        )
        .with_for_update()
    )
    if head is None:
        raise RuntimeError("tenant evidence chain head is unavailable")

    sequence_number = head.sequence_number + 1
    previous_hash = head.head_hash
    envelope = canonicalize_event({
        "customer_id": str(context.customer_id),
        "event": dict(event),
        "msp_id": str(context.msp_id),
        "subject": pseudonymous_subject,
    })
    event_hash = calculate_event_hash(previous_hash, envelope)
    event_id = uuid4()
    session.add(EvidenceEvent(
        id=event_id,
        msp_id=context.msp_id,
        customer_id=context.customer_id,
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        event_hash=event_hash,
        canonical_event=envelope,
        pseudonymous_subject=pseudonymous_subject,
    ))
    head.sequence_number = sequence_number
    head.head_hash = event_hash
    await session.flush()
    return AppendedEvidence(event_id, sequence_number, previous_hash, event_hash)


async def anchor_evidence_batch(
    session: AsyncSession,
    context: VerifiedTenantContext,
    first_sequence: int,
    kms_client: Any,
    s3_client: Any,
) -> EvidenceAnchorManifest:
    await _assert_session_scope(session, context)
    if context.customer_id is None:
        raise PermissionError("evidence anchors require a customer-scoped context")
    if first_sequence < 1:
        raise ValueError("evidence anchor sequence must be positive")
    previous_anchor = await session.scalar(
        select(func.max(EvidenceAnchorManifest.last_sequence)).where(
            EvidenceAnchorManifest.msp_id == context.msp_id,
            EvidenceAnchorManifest.customer_id == context.customer_id,
        )
    )
    expected_sequence = (previous_anchor or 0) + 1
    if first_sequence != expected_sequence:
        raise ValueError("evidence anchor batches must be contiguous and non-overlapping")
    events = list((await session.scalars(
        select(EvidenceEvent)
        .where(
            EvidenceEvent.msp_id == context.msp_id,
            EvidenceEvent.customer_id == context.customer_id,
            EvidenceEvent.sequence_number >= first_sequence,
        )
        .order_by(EvidenceEvent.sequence_number)
        .limit(MAX_ANCHOR_BATCH_SIZE)
    )).all())
    if not events or events[0].sequence_number != first_sequence:
        raise ValueError("evidence anchor batch has no first event")
    if any(event.sequence_number != first_sequence + offset for offset, event in enumerate(events)):
        raise ValueError("evidence anchor batch contains a sequence gap")
    event_hashes = [event.event_hash for event in events]
    root = calculate_merkle_root(event_hashes)
    last_sequence = events[-1].sequence_number
    key_arn = settings.EVIDENCE_KMS_KEY_ARN
    bucket = settings.EVIDENCE_BUCKET
    if not key_arn or not bucket:
        raise RuntimeError("evidence KMS key and Object Lock bucket must be configured")
    if not key_arn.startswith(f"arn:aws:kms:{settings.AWS_REGION}:"):
        raise RuntimeError("evidence signing key must be in the configured AWS region")

    manifest = {
        "schema_version": 1,
        "msp_id": str(context.msp_id),
        "customer_id": str(context.customer_id),
        "first_sequence": first_sequence,
        "last_sequence": last_sequence,
        "merkle_root_sha256": root.hex(),
        "kms_key_arn": key_arn,
        "signature_algorithm": "RSASSA_PSS_SHA_256",
    }
    manifest_bytes = canonicalize_event(manifest)
    sign_response = await asyncio.to_thread(
        kms_client.sign,
        KeyId=key_arn,
        Message=manifest_bytes,
        MessageType="RAW",
        SigningAlgorithm="RSASSA_PSS_SHA_256",
    )
    signature = sign_response["Signature"]
    object_body = canonicalize_event({
        "manifest": manifest,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    })
    object_key = (
        f"evidence/v1/{context.msp_id}/{context.customer_id}/"
        f"{first_sequence}-{last_sequence}-{root.hex()}.json"
    )
    retain_until = datetime.now(timezone.utc) + timedelta(days=settings.EVIDENCE_RETENTION_DAYS)
    await asyncio.to_thread(
        s3_client.put_object,
        Bucket=bucket,
        Key=object_key,
        Body=object_body,
        ContentType="application/json",
        ContentMD5=base64.b64encode(hashlib.md5(object_body, usedforsecurity=False).digest()).decode("ascii"),
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retain_until,
    )

    anchor = EvidenceAnchorManifest(
        id=uuid4(),
        msp_id=context.msp_id,
        customer_id=context.customer_id,
        first_sequence=first_sequence,
        last_sequence=last_sequence,
        merkle_root=root,
        kms_key_arn=key_arn,
        signature=signature,
        object_key=object_key,
    )
    session.add(anchor)
    await session.flush()
    return anchor
