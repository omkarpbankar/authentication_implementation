"""Migrations connect as the table owner, which is a different role from the running service."""

import asyncio
import os

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE = os.environ.get("APP8_MIGRATION_DATABASE", "access")
URL = f"postgresql+asyncpg://access_owner:access-owner-dev-password@127.0.0.1:5433/{DATABASE}"


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
