import asyncio
import hashlib
from uuid import uuid4

import pytest

from app.core.evidence import verify_evidence_chain
from app.services.evidence_chain import (
    ZERO_HASH,
    calculate_event_hash,
    calculate_merkle_root,
    canonicalize_event,
    pseudonymize_subject,
)
from app.models.v2 import EvidenceChainHead, EvidenceEvent


class FakeScalarResult:
    def __init__(self, values):
        self.values = values

    def all(self):
        return list(self.values)


class FakeEvidenceSession:
    def __init__(self, events, chain_head):
        self.events = events
        self.chain_head = chain_head
        self.query_count = 0
        self.statements = []

    def in_transaction(self):
        return True

    async def scalars(self, statement):
        self.statements.append(statement)
        self.query_count += 1
        if self.query_count == 1:
            return FakeScalarResult(
                event for event in self.events
                if event.pseudonymous_subject == DEVICE_REFERENCE
            )
        return FakeScalarResult(self.events)

    async def scalar(self, statement):
        self.statements.append(statement)
        return self.chain_head


DEVICE_REFERENCE = "hmac-sha256:" + "a" * 64


def make_evidence_chain():
    msp_id = uuid4()
    customer_id = uuid4()
    previous_hash = ZERO_HASH
    events = []
    for sequence_number in range(1, 4):
        payload = canonicalize_event({
            "event_type": "scan.completed",
            "sequence": sequence_number,
        })
        event_hash = calculate_event_hash(previous_hash, payload)
        events.append(EvidenceEvent(
            id=uuid4(),
            msp_id=msp_id,
            customer_id=customer_id,
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            event_hash=event_hash,
            canonical_event=payload,
            pseudonymous_subject=DEVICE_REFERENCE,
        ))
        previous_hash = event_hash
    chain_head = EvidenceChainHead(
        msp_id=msp_id,
        customer_id=customer_id,
        sequence_number=len(events),
        head_hash=previous_hash,
    )
    return events, chain_head


def test_canonicalize_event_uses_rfc8785_key_order():
    assert canonicalize_event({"z": "last", "a": 1}) == b'{"a":1,"z":"last"}'


def test_event_hash_chain_is_deterministic_and_ordered():
    first_event = canonicalize_event({"event_type": "scan", "sequence": 1})
    second_event = canonicalize_event({"event_type": "scan", "sequence": 2})
    first_hash = calculate_event_hash(ZERO_HASH, first_event)
    second_hash = calculate_event_hash(first_hash, second_event)

    assert first_hash == hashlib.sha256(ZERO_HASH + first_event).digest()
    assert second_hash == calculate_event_hash(first_hash, second_event)
    assert second_hash != calculate_event_hash(ZERO_HASH, second_event)


def test_event_hash_rejects_invalid_previous_digest():
    with pytest.raises(ValueError, match="SHA-256"):
        calculate_event_hash(b"short", b"{}")


def test_subject_pseudonym_is_keyed_and_stable():
    first_key = b"a" * 32
    second_key = b"b" * 32

    pseudonym = pseudonymize_subject(first_key, "device-123")
    assert pseudonym == pseudonymize_subject(first_key, "device-123")
    assert pseudonym != pseudonymize_subject(second_key, "device-123")
    assert pseudonym.startswith("hmac-sha256:")
    with pytest.raises(ValueError, match="256 bits"):
        pseudonymize_subject(b"short", "device-123")


def test_merkle_root_validates_and_preserves_leaf_order():
    leaves = [hashlib.sha256(b"first").digest(), hashlib.sha256(b"second").digest()]
    assert calculate_merkle_root([leaves[0]]) == leaves[0]
    assert calculate_merkle_root(leaves) != calculate_merkle_root(list(reversed(leaves)))
    with pytest.raises(ValueError, match="empty"):
        calculate_merkle_root([])


def test_evidence_chain_verifies_valid_chain():
    events, chain_head = make_evidence_chain()
    session = FakeEvidenceSession(events, chain_head)

    assert asyncio.run(verify_evidence_chain(session, DEVICE_REFERENCE)) is True


def test_evidence_chain_rejects_tampered_payload():
    events, chain_head = make_evidence_chain()
    events[1].canonical_event = canonicalize_event({
        "event_type": "scan.tampered",
        "sequence": 2,
    })
    session = FakeEvidenceSession(events, chain_head)

    assert asyncio.run(verify_evidence_chain(session, DEVICE_REFERENCE)) is False
