"""Database helpers. Every tenant-owned read or write runs inside a tenant transaction."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from apps.app8_access.access_service.settings import settings

engine: AsyncEngine = create_async_engine(settings.database_url, pool_size=20, max_overflow=10)


async def set_tenant(db: AsyncConnection, tenant_id: UUID) -> None:
    await db.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)})


@asynccontextmanager
async def tenant_tx(tenant_id: UUID | None = None) -> AsyncIterator[AsyncConnection]:
    async with engine.begin() as db:
        await set_tenant(db, tenant_id or "")
        yield db


async def one(db: AsyncConnection, sql: str, **params) -> dict | None:
    row = (await db.execute(text(sql), params)).mappings().first()
    return dict(row) if row else None


async def many(db: AsyncConnection, sql: str, **params) -> list[dict]:
    return [dict(row) for row in (await db.execute(text(sql), params)).mappings().all()]


async def run(db: AsyncConnection, sql: str, **params) -> None:
    await db.execute(text(sql), params)


async def audit(
    db: AsyncConnection,
    tenant_id: UUID,
    actor_id: UUID | None,
    action: str,
    target: str = "",
    *,
    before: str | None = None,
    after: str | None = None,
    reason: str = "",
    reference_id: str = "",
) -> None:
    await run(
        db,
        """
        INSERT INTO access_audit_log
            (tenant_id, actor_id, action, target, before, after, reason, reference_id)
        VALUES (:t, :a, :x, :o, CAST(:b AS jsonb), CAST(:c AS jsonb), :r, :f)
        """,
        t=tenant_id,
        a=actor_id,
        x=action,
        o=target,
        b=before,
        c=after,
        r=reason,
        f=reference_id,
    )
