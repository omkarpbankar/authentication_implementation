"""Create App 8's databases and roles, run migrations, and load the application catalog.

Run:  uv run python scripts/setup_access_db.py
"""

import asyncio
import os
import subprocess
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, ".")
from apps.app8_access.catalog import APPLICATIONS, TIERS  # noqa: E402
from scripts.livecheck import ROOT  # noqa: E402
from scripts.setup_platform_db import database_exists, psql  # noqa: E402

ISSUER = "http://localhost:8080/realms/course"
ROLES_SQL = """
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'access_owner') THEN
    CREATE ROLE access_owner LOGIN PASSWORD 'access-owner-dev-password' NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'access_app') THEN
    CREATE ROLE access_app LOGIN PASSWORD 'access-app-dev-password' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
"""


async def seed(database: str) -> None:
    url = f"postgresql+asyncpg://access_owner:access-owner-dev-password@127.0.0.1:5433/{database}"
    engine = create_async_engine(url)
    async with engine.begin() as db:
        for slug, name in (("acme", "Acme"), ("globex", "Globex")):
            await db.execute(
                text(
                    "INSERT INTO tenants (slug, name) VALUES (:s, :n) ON CONFLICT (slug) DO NOTHING"
                ),
                {"s": slug, "n": name},
            )
        for key, app in APPLICATIONS.items():
            await db.execute(
                text("""
                INSERT INTO applications (id, app_key, name) VALUES (:i, :k, :n)
                ON CONFLICT (id) DO NOTHING
                """),
                {"i": app["id"], "k": key, "n": app["name"]},
            )
            await db.execute(
                text("""
                INSERT INTO application_clients (issuer, client_id, application_id)
                VALUES (:iss, :c, :a) ON CONFLICT DO NOTHING
                """),
                {"iss": ISSUER, "c": app["client_id"], "a": app["id"]},
            )
            for tier, rank in TIERS.items():
                await db.execute(
                    text("""
                    INSERT INTO tiers (application_id, key, rank) VALUES (:a, :k, :r)
                    ON CONFLICT (application_id, key) DO NOTHING
                    """),
                    {"a": app["id"], "k": tier, "r": rank},
                )
            for feature, by_tier in app["features"].items():
                await db.execute(
                    text("""
                    INSERT INTO features (application_id, key) VALUES (:a, :k)
                    ON CONFLICT (key) DO NOTHING
                    """),
                    {"a": app["id"], "k": feature},
                )
                for tier, limit in by_tier.items():
                    await db.execute(
                        text("""
                        INSERT INTO tier_features (tier_id, feature_id, limit_value)
                        SELECT t.id, f.id, :l FROM tiers t, features f
                        WHERE t.application_id = :a AND t.key = :t AND f.key = :f
                        ON CONFLICT DO NOTHING
                        """),
                        {"a": app["id"], "t": tier, "f": feature, "l": limit},
                    )
    await engine.dispose()


if __name__ == "__main__":
    psql(ROLES_SQL)
    for database in ("access", "access_test"):
        if not database_exists(database):
            psql(f"CREATE DATABASE {database} OWNER access_owner;")
        psql(f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;")
        psql(f"GRANT CONNECT ON DATABASE {database} TO access_owner, access_app;")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                "apps/app8_access/access_service/alembic.ini",
                "upgrade",
                "head",
            ],
            cwd=ROOT,
            check=True,
            env={**os.environ, "APP8_MIGRATION_DATABASE": database},
        )
        asyncio.run(seed(database))
    print("Databases are ready: access, access_test")
