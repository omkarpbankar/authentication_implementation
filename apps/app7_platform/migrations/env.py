"""Migrations connect as the table owner, which is a different role from the running app."""

import asyncio
import os

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE = os.environ.get("APP7_MIGRATION_DATABASE", "platform")
URL = f"postgresql+asyncpg://platform_owner:owner-dev-password@127.0.0.1:5433/{DATABASE}"


def run(connection) -> None:
    context.configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def main() -> None:
    engine = create_async_engine(URL)
    async with engine.connect() as connection:
        await connection.run_sync(run)
    await engine.dispose()


asyncio.run(main())
