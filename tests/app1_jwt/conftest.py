import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

from apps.app1_jwt import main
from apps.app1_jwt.keys import KeyRing
from apps.app1_jwt.settings import settings
from apps.app1_jwt.store import Store

EMAIL = "asha@example.com"
PASSWORD = "correct-horse-battery"


@pytest.fixture
def ring(tmp_path):
    return KeyRing.load_or_create(tmp_path)


@pytest.fixture
def redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def client(ring, redis):
    main.app.dependency_overrides[main.get_key_ring] = lambda: ring
    main.app.dependency_overrides[main.get_store] = lambda: Store(
        redis, settings.refresh_ttl_seconds
    )
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


@pytest.fixture
def tokens(client):
    client.post("/auth/register", json={"email": EMAIL, "password": PASSWORD})
    return client.post("/auth/login", data={"username": EMAIL, "password": PASSWORD}).json()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}
