"""Create App 7's databases and roles, then run its migrations.

Runs psql inside the Postgres container, so it never needs your .env file. The role passwords
are public practice values, reachable only from this computer.

Run:  uv run python scripts/setup_platform_db.py
"""

import os
import subprocess
import sys

sys.path.insert(0, ".")
from scripts.livecheck import ROOT  # noqa: E402

ROLES_SQL = """
DO $$
BEGIN
  -- Owns the tables and runs migrations. The app never connects as this role.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'platform_owner') THEN
    CREATE ROLE platform_owner LOGIN PASSWORD 'owner-dev-password' NOSUPERUSER NOBYPASSRLS;
  END IF;
  -- The role the app uses. It cannot skip row-level security.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'platform_app') THEN
    CREATE ROLE platform_app LOGIN PASSWORD 'app-dev-password' NOSUPERUSER NOBYPASSRLS;
  END IF;
  -- Audited support access, limited by time-boxed grants.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'platform_support') THEN
    CREATE ROLE platform_support LOGIN PASSWORD 'support-dev-password' NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
"""


def psql(sql: str, database: str = "") -> None:
    # sh expands the variables inside the container, so their values are never seen here.
    target = database or "$POSTGRES_DB"
    subprocess.run(
        [
            "docker", "compose", "exec", "-T", "postgres", "sh", "-c",
            f'psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d "{target}"',
        ],
        input=sql,
        text=True,
        cwd=ROOT,
        check=True,
    )  # fmt: skip


def database_exists(name: str) -> bool:
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "postgres", "sh", "-c",
            f"""psql -tA -U "$POSTGRES_USER" -d "$POSTGRES_DB" """
            f"""-c "SELECT 1 FROM pg_database WHERE datname = '{name}'" """,
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )  # fmt: skip
    return result.stdout.strip() == "1"


def setup_database(name: str) -> None:
    if not database_exists(name):
        psql(f"CREATE DATABASE {name} OWNER platform_owner;")
    psql(f"REVOKE ALL ON DATABASE {name} FROM PUBLIC;")
    psql(f"GRANT CONNECT ON DATABASE {name} TO platform_owner, platform_app, platform_support;")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "apps/app7_platform/alembic.ini",
            "upgrade",
            "head",
        ],
        cwd=ROOT,
        check=True,
        env={**os.environ, "APP7_MIGRATION_DATABASE": name},
    )


if __name__ == "__main__":
    psql(ROLES_SQL)
    for database in ("platform", "platform_test"):
        setup_database(database)
    print("Databases are ready: platform, platform_test")
