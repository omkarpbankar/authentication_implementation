"""Make the first Super Admin. There is no public way to do this, on purpose.

The person signs in to any App 8 app once, so that their user record exists. Then run:
    uv run python -m apps.app8_access.access_service.bootstrap_admin meera@acme.example acme
"""

import asyncio
import sys

from sqlalchemy.ext.asyncio import create_async_engine

from apps.app8_access.access_service import db as database
from apps.app8_access.access_service.db import audit, one, run
from apps.app8_access.access_service.settings import settings


async def promote(email: str, tenant_slug: str) -> str:
    # Each run opens its own engine, so this also works from a one-off command.
    database.engine = create_async_engine(settings.database_url)
    async with database.tenant_tx() as db:
        tenant = await one(db, "SELECT id FROM tenants WHERE slug = :s", s=tenant_slug)
        user = await one(db, "SELECT id FROM users WHERE lower(email) = :e", e=email.lower())
    if tenant is None or user is None:
        return "Not found. Has this person signed in to an App 8 app yet?"

    async with database.tenant_tx(tenant["id"]) as db:
        await run(
            db,
            """
            INSERT INTO admin_roles (tenant_id, user_id, role) VALUES (:t, :u, 'super_admin')
            ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = 'super_admin'
            """,
            t=tenant["id"],
            u=user["id"],
        )
        await run(
            db,
            "INSERT INTO tenant_users VALUES (:t, :u) ON CONFLICT DO NOTHING",
            t=tenant["id"],
            u=user["id"],
        )
        await audit(db, tenant["id"], None, "admin.bootstrapped", email)
    await database.engine.dispose()
    return f"{email} is now a Super Admin of {tenant_slug}."


if __name__ == "__main__":
    print(asyncio.run(promote(sys.argv[1], sys.argv[2])))
