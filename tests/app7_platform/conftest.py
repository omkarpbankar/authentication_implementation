"""App 7 tests use real Postgres, connecting as the real restricted role.

Row-level security lives in the database, so a fake database would prove nothing.
Setup:  uv run python scripts/setup_platform_db.py
"""

import asyncio
import os
import socket
import uuid

os.environ["APP7_DATABASE_URL"] = (
    "postgresql+asyncpg://platform_app:app-dev-password@127.0.0.1:5433/platform_test"
)
os.environ["APP7_SUPPORT_DATABASE_URL"] = (
    "postgresql+asyncpg://platform_support:support-dev-password@127.0.0.1:5433/platform_test"
)

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from apps.app1_jwt.keys import KeyRing
from apps.app2_oidc.oidc import OidcProvider
from apps.app7_platform import auth, database, main
from apps.app7_platform.identity import KeycloakAdapter, TokenVerifier
from apps.shared.rate_limit import RateLimiter
from tests.fake_idp import FakeIdp

APP_URL = os.environ["APP7_DATABASE_URL"]
SUPPORT_URL = os.environ["APP7_SUPPORT_DATABASE_URL"]
OWNER_URL = APP_URL.replace("platform_app:app-dev-password", "platform_owner:owner-dev-password")


def pytest_collection_modifyitems(items):
    with socket.socket() as probe:
        probe.settimeout(1)
        reachable = probe.connect_ex(("127.0.0.1", 5433)) == 0
    if not reachable:
        skip = pytest.mark.skip(reason="Postgres is not running")
        for item in items:
            if "app7_platform" in str(item.fspath):
                item.add_marker(skip)


def run_sql(url: str, sql: str, params: dict | None = None, *, tenant=None, user=None):
    """Run one statement as a chosen role, in its own transaction, and return the rows."""

    async def go():
        engine = create_async_engine(url, poolclass=NullPool)
        async with engine.begin() as connection:
            await database.set_context(connection, tenant, user)
            result = await connection.execute(text(sql), params or {})
            found = [dict(row) for row in result.mappings().all()] if result.returns_rows else []
        await engine.dispose()
        return found

    return asyncio.run(go())


class Person:
    def __init__(self, harness, name):
        self.harness = harness
        self.subject = f"{name}-{uuid.uuid4().hex[:8]}"
        self.email = f"{self.subject}@test.example"
        self.idp_token = harness.idp.token("app7-platform", sub=self.subject, email=self.email)
        self.client = harness.client

    def idp_headers(self):
        return {"Authorization": f"Bearer {self.idp_token}"}

    def user_id(self):
        rows = run_sql(
            OWNER_URL,
            "SELECT user_id FROM user_identities WHERE subject = :s",
            {"s": self.subject},
        )
        return str(rows[0]["user_id"])

    def enter(self, slug):
        response = self.client.post("/session", json={"tenant": slug}, headers=self.idp_headers())
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}


class Harness:
    def __init__(self, client, idp):
        self.client = client
        self.idp = idp

    def person(self, name="user"):
        return Person(self, name)

    def tenant(self, owner, name="acme"):
        slug = f"{name}-{uuid.uuid4().hex[:8]}"
        response = self.client.post(
            "/tenants", json={"slug": slug, "name": name}, headers=owner.idp_headers()
        )
        assert response.status_code == 201, response.text
        return slug, response.json()["id"]

    def member(self, owner_headers, slug, role, clearance=0, name=None):
        """Add a person to a tenant with a role, then return them and their headers."""
        person = self.person(name or role)
        self.client.get("/me/tenants", headers=person.idp_headers())
        response = self.client.post(
            f"/t/{slug}/members",
            json={"user_id": person.user_id(), "role": role, "clearance": clearance},
            headers=owner_headers,
        )
        assert response.status_code == 201, response.text
        return person, person.enter(slug)


@pytest.fixture
def h(tmp_path, monkeypatch):
    idp = FakeIdp()
    # NullPool, because the test client runs each request on its own event loop.
    monkeypatch.setattr(database, "engine", create_async_engine(APP_URL, poolclass=NullPool))
    monkeypatch.setattr(
        main, "support_engine", create_async_engine(SUPPORT_URL, poolclass=NullPool)
    )
    # The test client opens a new event loop for each request, so a shared connection
    # from the real limiter would not survive between requests.
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(auth, "get_limiter", lambda: RateLimiter(fake_redis))
    ring = KeyRing.load_or_create(tmp_path)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        verifier = TokenVerifier([KeycloakAdapter(OidcProvider(idp.issuer), "app7-platform")])
        main.app.dependency_overrides[auth.get_verifier] = lambda: verifier
        main.app.dependency_overrides[auth.get_key_ring] = lambda: ring
        yield Harness(TestClient(main.app), idp)
        main.app.dependency_overrides.clear()
