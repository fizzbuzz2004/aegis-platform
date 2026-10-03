from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import AsyncIterator
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

_v2_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


@dataclass(frozen=True)
class VerifiedTenantContext:
    user_id: UUID
    msp_id: UUID
    customer_id: UUID | None


def _verified_context_from_token(token: str) -> VerifiedTenantContext:
    try:
        claims = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = UUID(claims["uid"])
        msp_id = UUID(claims["msp_id"])
        customer_claim = claims.get("customer_id")
        customer_id = UUID(customer_claim) if customer_claim else None
    except (JWTError, KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid signed tenant-scope claims are required",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    return VerifiedTenantContext(user_id, msp_id, customer_id)


async def get_verified_tenant_context(
    token: str = Depends(_v2_oauth2_scheme),
) -> VerifiedTenantContext:
    return _verified_context_from_token(token)


def _async_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if database_url.startswith("sqlite://"):
        return database_url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    if "+asyncpg://" in database_url or "+aiosqlite://" in database_url:
        return database_url
    raise ValueError("V2 database URL must use PostgreSQL or SQLite")


@lru_cache(maxsize=1)
def _session_factory() -> async_sessionmaker[AsyncSession]:
    if not settings.AEGIS_V2_DATABASE_URL:
        raise RuntimeError("AEGIS_V2_DATABASE_URL must use the non-owner aegis_app database role")
    engine_options: dict[str, object] = {"pool_pre_ping": True}
    if settings.AEGIS_V2_DATABASE_URL.startswith("postgresql"):
        engine_options.update(pool_size=5, max_overflow=10)
    engine = create_async_engine(_async_database_url(settings.AEGIS_V2_DATABASE_URL), **engine_options)
    return async_sessionmaker(engine, expire_on_commit=False)


async def set_transaction_tenant_context(
    session: AsyncSession,
    context: VerifiedTenantContext,
) -> None:
    if not session.in_transaction():
        raise RuntimeError("Tenant context must be set inside an active transaction")
    await session.execute(
        text(
            "SELECT "
            "set_config('app.user_id', :user_id, true), "
            "set_config('app.msp_id', :msp_id, true), "
            "set_config('app.customer_id', :customer_id, true)"
        ),
        {
            "user_id": str(context.user_id),
            "msp_id": str(context.msp_id),
            "customer_id": str(context.customer_id) if context.customer_id else "",
        },
    )


async def get_v2_session(
    context: VerifiedTenantContext = Depends(get_verified_tenant_context),
) -> AsyncIterator[AsyncSession]:
    async with _session_factory()() as session:
        async with session.begin():
            await set_transaction_tenant_context(session, context)
            yield session
