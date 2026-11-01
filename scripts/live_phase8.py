"""Live check for App 7: real Keycloak logins, a real server, and real Postgres.

Run:  uv run python scripts/setup_platform_db.py
      uv run python scripts/live_phase8.py
"""

import asyncio
import secrets
import sys

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, ".")
from scripts.livecheck import Report, servers  # noqa: E402

API = "http://localhost:8008"
TOKEN_URL = "http://localhost:8080/realms/course/protocol/openid-connect/token"
ISSUER = "http://localhost:8080/realms/course"
APP_DB = "postgresql+asyncpg://platform_app:app-dev-password@127.0.0.1:5433/platform"
OWNER_DB = "postgresql+asyncpg://platform_owner:owner-dev-password@127.0.0.1:5433/platform"


def keycloak_token(username: str) -> dict:
    response = httpx.post(
        TOKEN_URL,
        data={
            "grant_type": "password",
            "client_id": "app7-tester",
            "client_secret": "app7-tester-dev-secret",
            "username": username,
            "password": "correct-horse-battery",
            "scope": "openid organization",
        },
    )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def sql(url: str, statement: str, params: dict | None = None) -> list:
    engine = create_async_engine(url)
    async with engine.begin() as connection:
        result = await connection.execute(text(statement), params or {})
        rows = result.all() if result.returns_rows else []
    await engine.dispose()
    return rows


def main() -> None:
    report = Report()
    asha, ravi = keycloak_token("asha"), keycloak_token("ravi")
    slug = f"acme-{secrets.token_hex(3)}"

    with servers(("apps.app7_platform.main:app", 8008)):
        tenant = httpx.post(f"{API}/tenants", json={"slug": slug, "name": "Acme"}, headers=asha)
        report.check("A signed-in user can create a tenant", tenant.status_code == 201)
        tenant_id = tenant.json()["id"]

        session = httpx.post(f"{API}/session", json={"tenant": slug}, headers=asha).json()
        owner = {"Authorization": f"Bearer {session['access_token']}"}
        report.check("Creator is the owner", session["role"] == "owner")

        project = httpx.post(
            f"{API}/t/{slug}/projects", json={"name": "Launch"}, headers=owner
        ).json()
        document = httpx.post(
            f"{API}/t/{slug}/projects/{project['id']}/documents",
            json={"title": "Plan"},
            headers=owner,
        ).json()
        report.check("Owner can create a document", document["title"] == "Plan")

        blocked = httpx.post(f"{API}/session", json={"tenant": slug}, headers=ravi)
        report.check("Another company's user is refused", blocked.status_code == 403)

        asyncio.run(
            sql(
                OWNER_DB,
                """INSERT INTO tenant_idp_connections VALUES (:i, 'globex', :t)
                   ON CONFLICT (issuer, external_tenant_id) DO UPDATE SET tenant_id = :t""",
                {"i": ISSUER, "t": tenant_id},
            )
        )
        joined = httpx.post(f"{API}/session", json={}, headers=ravi).json()
        report.check(
            "A mapped organization joins the right tenant, with a mapped role",
            joined.get("tenant") == slug and joined.get("role") == "viewer",
        )
        ravi_headers = {"Authorization": f"Bearer {joined['access_token']}"}
        denied = httpx.post(f"{API}/t/{slug}/projects", json={"name": "x"}, headers=ravi_headers)
        report.check("A viewer cannot create projects", denied.status_code == 403)

        rows = asyncio.run(sql(APP_DB, "SELECT * FROM documents"))
        report.check("The app role sees no rows with no tenant set", rows == [])

        asyncio.run(
            sql(OWNER_DB, "DELETE FROM tenant_idp_connections WHERE external_tenant_id = 'globex'")
        )
        httpx.post(f"{API}/t/{slug}/suspend", headers=owner)
        after = httpx.get(f"{API}/t/{slug}/documents", headers=owner)
        report.check("Suspension blocks a live token at once", after.status_code == 403)
    report.finish()


if __name__ == "__main__":
    main()
