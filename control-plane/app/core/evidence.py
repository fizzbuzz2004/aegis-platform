from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.v2 import EvidenceChainHead, EvidenceEvent
from app.services.evidence_chain import verify_evidence_chain_events


async def verify_evidence_chain(session: AsyncSession, device_id: str) -> bool:
    """Verify chains containing a tenant-keyed pseudonymous device reference."""
    if not device_id or not session.in_transaction():
        return False

    matching_events = await session.scalars(
        select(EvidenceEvent)
        .where(EvidenceEvent.pseudonymous_subject == device_id)
        .order_by(EvidenceEvent.msp_id, EvidenceEvent.customer_id, EvidenceEvent.sequence_number)
    )
    scopes = {(event.msp_id, event.customer_id) for event in matching_events.all()}
    if not scopes:
        return False

    for msp_id, customer_id in scopes:
        chain_result = await session.scalars(
            select(EvidenceEvent)
            .where(
                EvidenceEvent.msp_id == msp_id,
                EvidenceEvent.customer_id == customer_id,
            )
            .order_by(EvidenceEvent.sequence_number)
        )
        chain_events = list(chain_result.all())
        if not verify_evidence_chain_events(chain_events):
            return False

        chain_head = await session.scalar(
            select(EvidenceChainHead).where(
                EvidenceChainHead.msp_id == msp_id,
                EvidenceChainHead.customer_id == customer_id,
            )
        )
        if chain_head is None or chain_head.sequence_number != len(chain_events):
            return False
        if not chain_events or chain_head.head_hash != chain_events[-1].event_hash:
            return False

    return True
