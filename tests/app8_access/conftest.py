"""App 8 tests use real Postgres, so row-level security and transactions are the real thing.

Each test gets its own tenant and application, so tests cannot affect one another.
Setup:  uv run python scripts/setup_access_db.py
"""

import asyncio
import os
import socket
import time
import uuid

os.environ["APP8_DATABASE_URL"] = (
    "postgresql+asyncpg://access_app:access-app-dev-password@127.0.0.1:5433/access_test"
)

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from apps.app2_oidc.oidc import OidcProvider
from apps.app8_access.access_service import core
from apps.app8_access.access_service import db as database
from apps.app8_access.access_service import main as service
from apps.app8_access.access_service.settings import settings
from tests.fake_idp import FakeIdp

APP_URL = os.environ["APP8_DATABASE_URL"]
OWNER_URL = APP_URL.replace(
    "access_app:access-app-dev-password", "access_owner:access-owner-dev-password"
)


def pytest_collection_modifyitems(items):
    with socket.socket() as probe:
        probe.settimeout(1)
        reachable = probe.connect_ex(("127.0.0.1", 5433)) == 0
    if not reachable:
        skip = pytest.mark.skip(reason="Postgres is not running")
        for item in items:
            if "test_service" in str(item.fspath):
                item.add_marker(skip)


def run_sql(url: str, sql: str, params: dict | None = None, *, tenant=None):
    async def go():
        engine = create_async_engine(url, poolclass=NullPool)
        async with engine.begin() as connection:
            await connection.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant or "")}
            )
            result = await connection.execute(text(sql), params or {})
            found = [dict(row) for row in result.mappings().all()] if result.returns_rows else []
        await engine.dispose()
        return found

    return asyncio.run(go())


class Application:
    def __init__(self, harness):
        self.harness = harness
        self.id = uuid.uuid4()
        self.key = f"app-{uuid.uuid4().hex[:8]}"
        self.client_id = f"client-{self.key}"
        run_sql(
            OWNER_URL,
            "INSERT INTO applications (id, app_key, name) VALUES (:i, :k, :k)",
            {"i": self.id, "k": self.key},
        )
        run_sql(
            OWNER_URL,
            "INSERT INTO application_clients (issuer, client_id, application_id) VALUES (:s,:c,:a)",
            {"s": settings.issuer, "c": self.client_id, "a": self.id},
        )
        self.tier_ids = {}
        for tier, rank in {"basic": 10, "standard": 20, "premium": 30}.items():
            self.tier_ids[tier] = run_sql(
                OWNER_URL,
                "INSERT INTO tiers (application_id, key, rank) VALUES (:a, :k, :r) RETURNING id",
                {"a": self.id, "k": tier, "r": rank},
            )[0]["id"]
        self.feature(f"{self.key}.read", {"basic": None, "standard": None, "premium": None})
        self.feature(f"{self.key}.create", {"basic": 50, "standard": None, "premium": None})
        self.feature(f"{self.key}.export", {"premium": None})

    def feature(self, key, by_tier):
        feature_id = run_sql(
            OWNER_URL,
            "INSERT INTO features (application_id, key) VALUES (:a, :k) RETURNING id",
            {"a": self.id, "k": key},
        )[0]["id"]
        for tier, limit in by_tier.items():
            run_sql(
                OWNER_URL,
                "INSERT INTO tier_features VALUES (:t, :f, :l)",
                {"t": self.tier_ids[tier], "f": feature_id, "l": limit},
            )

    def status(self, value):
        run_sql(OWNER_URL, "UPDATE applications SET status = :s WHERE id = :i",
                {"s": value, "i": self.id})  # fmt: skip

    def service_headers(self):
        token = self.harness.idp.token("access-service", azp=self.client_id, sub=self.client_id)
        return {"Authorization": f"Bearer {token}"}


class Tenant:
    def __init__(self, harness):
        self.harness = harness
        self.slug = f"t-{uuid.uuid4().hex[:8]}"
        self.id = run_sql(
            OWNER_URL,
            "INSERT INTO tenants (slug, name) VALUES (:s, :s) RETURNING id",
            {"s": self.slug},
        )[0]["id"]

    def admin(self, role="super_admin", application=None, **claims):
        subject = f"admin-{uuid.uuid4().hex[:8]}"
        email = f"{subject}@test.example"
        user_id = run_sql(
            OWNER_URL,
            "INSERT INTO users (issuer, subject, email) VALUES (:i, :s, :e) RETURNING id",
            {"i": settings.issuer, "s": subject, "e": email},
        )[0]["id"]
        run_sql(
            OWNER_URL,
            "INSERT INTO admin_roles (tenant_id, user_id, role, application_id)"
            " VALUES (:t, :u, :r, :a)",
            {"t": self.id, "u": user_id, "r": role, "a": application.id if application else None},
            tenant=self.id,
        )
        defaults = {
            "sub": subject,
            "email": email,
            "amr": ["pwd", "otp"],
            "organization": [self.slug],
            "auth_time": int(time.time()),
        }
        token = self.harness.idp.token("access-service", **{**defaults, **claims})
        return Admin(self.harness, user_id, {"Authorization": f"Bearer {token}"})

    def person(self, app=None):
        """A user, created the way real users are: by arriving at an app."""
        person = Person(self.harness, self)
        if app:
            person.evaluate(app)
        return person


class Admin:
    def __init__(self, harness, user_id, headers):
        self.client = harness.client
        self.id = user_id
        self.headers = headers

    def grant(self, person, app, tier="basic", **fields):
        body = {"tier": tier, "reason": "test grant", **fields}
        return self.client.put(
            f"/admin/v1/users/{person.user_id()}/grants/{app.id}", json=body, headers=self.headers
        )

    def post(self, path, **body):
        return self.client.post(f"/admin/v1{path}", json=body, headers=self.headers)

    def get(self, path, **params):
        return self.client.get(f"/admin/v1{path}", params=params, headers=self.headers)


class Person:
    def __init__(self, harness, tenant):
        self.harness = harness
        self.tenant = tenant
        self.subject = f"user-{uuid.uuid4().hex[:10]}"
        self.email = f"{self.subject}@test.example"

    def payload(self, app, feature="", usage=None):
        return {
            "subject": {
                "type": "user",
                "id": self.subject,
                "properties": {"email": self.email, "issuer": settings.issuer, "name": "Test"},
            },
            "resource": {"type": "application", "id": str(app.id)},
            "action": {"name": "use"},
            "context": {"tenant": self.tenant.slug, "feature": feature, "usage": usage},
        }

    def evaluate(self, app, feature="", usage=None):
        response = self.harness.client.post(
            "/access/v1/evaluation",
            json=self.payload(app, feature, usage),
            headers=app.service_headers(),
        )
        assert response.status_code == 200, response.text
        return response.json()

    def reason(self, app, feature="", usage=None):
        return self.evaluate(app, feature, usage)["context"].get("reason_code")

    def user_id(self):
        return run_sql(OWNER_URL, "SELECT id FROM users WHERE subject = :s", {"s": self.subject})[
            0
        ]["id"]


class Harness:
    def __init__(self, client, idp, redis):
        self.client = client
        self.idp = idp
        self.redis = redis

    def application(self):
        return Application(self)

    def tenant(self):
        return Tenant(self)


@pytest.fixture
def h(monkeypatch):
    idp = FakeIdp(settings.issuer)
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(database, "engine", create_async_engine(APP_URL, poolclass=NullPool))
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        provider = OidcProvider(idp.issuer)
        service.app.dependency_overrides[core.get_provider] = lambda: provider
        service.app.dependency_overrides[core.get_redis] = lambda: redis
        yield Harness(TestClient(service.app), idp, redis)
        service.app.dependency_overrides.clear()
