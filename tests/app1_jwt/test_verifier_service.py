import time

import jwt
import pytest
from fastapi.testclient import TestClient

from apps.app1_jwt import verifier_service
from apps.app1_jwt.keys import KeyRing
from apps.app1_jwt.tokens import create_access_token


class FakeJwksClient(jwt.PyJWKClient):
    """Serves JWKS from memory, so no App 1 server has to be running."""

    def __init__(self, ring):
        super().__init__("http://unused.invalid/jwks")
        self.ring = ring

    def fetch_data(self):
        return self.ring.jwks()


@pytest.fixture
def ring(tmp_path):
    return KeyRing.load_or_create(tmp_path)


@pytest.fixture
def client(ring):
    app = verifier_service.app
    app.dependency_overrides[verifier_service.get_jwks_client] = lambda: FakeJwksClient(ring)
    yield TestClient(app)
    app.dependency_overrides.clear()


def token_for(ring, audience="app1-api"):
    return create_access_token(ring, "asha", "f", "http://localhost:8001", audience, 60)


def test_verifies_with_only_the_public_jwks(client, ring):
    headers = {"Authorization": f"Bearer {token_for(ring)}"}
    assert client.get("/whoami", headers=headers).json()["user_id"] == "asha"


def test_rejects_the_wrong_audience(client, ring):
    headers = {"Authorization": f"Bearer {token_for(ring, 'other-api')}"}
    assert client.get("/whoami", headers=headers).status_code == 401


def test_rejects_a_missing_token(client):
    assert client.get("/whoami").status_code == 401


def test_rejects_an_expired_token(client, ring):
    now = int(time.time()) - 100
    token = jwt.encode(
        {
            "iss": "http://localhost:8001",
            "aud": "app1-api",
            "sub": "a",
            "exp": now,
            "typ": "access",
        },
        ring.active_key,
        algorithm="RS256",
        headers={"kid": ring.active_kid},
    )
    assert client.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401
