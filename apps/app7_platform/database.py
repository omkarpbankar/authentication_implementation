"""Database access. Each transaction states which tenant it is acting for."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from apps.app7_platform.settings import settings

engine: AsyncEngine = create_async_engine(settings.database_url, pool_size=10)
support_engine: AsyncEngine = create_async_engine(settings.support_database_url, pool_size=2)


async def set_context(
    connection: AsyncConnection, tenant_id: UUID | None = None, user_id: UUID | None = None
) -> None:
    # The final "true" limits the value to this transaction. A session-level value would stay
    # on the pooled connection, and leak into the next request, which may be another tenant.
    await connection.execute(
        text(
            "SELECT set_config('app.tenant_id', :tenant, true),"
            " set_config('app.user_id', :user, true)"
        ),
        {"tenant": str(tenant_id or ""), "user": str(user_id or "")},
    )


@asynccontextmanager
async def tenant_transaction(
    tenant_id: UUID | None = None,
    user_id: UUID | None = None,
    database: AsyncEngine | None = None,
) -> AsyncIterator[AsyncConnection]:
    """Commits on success, and rolls back on any error."""
    async with (database or engine).begin() as connection:
        await set_context(connection, tenant_id, user_id)
        yield connection
