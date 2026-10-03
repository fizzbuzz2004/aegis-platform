import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.security import create_access_token
from app.core.v2_database import (
    VerifiedTenantContext,
    _async_database_url,
    _verified_context_from_token,
    set_transaction_tenant_context,
)


class RecordingSession:
    def __init__(self, active_transaction=True):
        self.active_transaction = active_transaction
        self.statement = None
        self.parameters = None

    def in_transaction(self):
        return self.active_transaction

    async def execute(self, statement, parameters):
        self.statement = str(statement)
        self.parameters = parameters


def test_signed_scope_claims_create_verified_context():
    user_id, msp_id, customer_id = uuid4(), uuid4(), uuid4()
    token = create_access_token({
        "sub": "principal",
        "uid": str(user_id),
        "msp_id": str(msp_id),
        "customer_id": str(customer_id),
    })

    assert _verified_context_from_token(token) == VerifiedTenantContext(user_id, msp_id, customer_id)


def test_legacy_or_invalid_tokens_fail_closed_for_v2_scope():
    legacy_token = create_access_token({"sub": "legacy-user"})
    with pytest.raises(HTTPException) as error:
        _verified_context_from_token(legacy_token)
    assert error.value.status_code == 401

    with pytest.raises(HTTPException) as error:
        _verified_context_from_token("invalid-token")
    assert error.value.status_code == 401


def test_tenant_context_is_set_transaction_locally_with_bound_values():
    context = VerifiedTenantContext(uuid4(), uuid4(), uuid4())
    session = RecordingSession()

    asyncio.run(set_transaction_tenant_context(session, context))

    assert "set_config('app.user_id', :user_id, true)" in session.statement
    assert "set_config('app.msp_id', :msp_id, true)" in session.statement
    assert "set_config('app.customer_id', :customer_id, true)" in session.statement
    assert session.parameters == {
        "user_id": str(context.user_id),
        "msp_id": str(context.msp_id),
        "customer_id": str(context.customer_id),
    }


def test_tenant_context_requires_an_active_transaction():
    context = VerifiedTenantContext(uuid4(), uuid4(), None)
    session = RecordingSession(active_transaction=False)

    with pytest.raises(RuntimeError, match="active transaction"):
        asyncio.run(set_transaction_tenant_context(session, context))


def test_async_database_url_uses_async_drivers():
    assert _async_database_url("postgresql://user:pass@db/aegis") == "postgresql+asyncpg://user:pass@db/aegis"
    assert _async_database_url("sqlite:///test.db") == "sqlite+aiosqlite:///test.db"
    with pytest.raises(ValueError, match="PostgreSQL or SQLite"):
        _async_database_url("mysql://db/aegis")
