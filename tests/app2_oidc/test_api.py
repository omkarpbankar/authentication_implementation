import time

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from apps.app2_oidc import api
from apps.app2_oidc.oidc import CLOCK_SKEW_SECONDS, OidcProvider, new_pkce_pair
from tests.fake_idp import FakeIdp


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def client(idp):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        provider = OidcProvider(idp.issuer)
        api.app.dependency_overrides[api.get_provider] = lambda: provider
        yield TestClient(api.app)
        api.app.dependency_overrides.clear()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_valid_token_is_accepted(client, idp):
    response = client.get("/api/whoami", headers=bearer(idp.token("app2-api")))
    assert response.status_code == 200


def test_id_token_is_rejected_by_the_api(client, idp):
    """An ID token's audience is the web client, so the API must refuse it."""
    response = client.get("/api/whoami", headers=bearer(idp.token("app2-web", nonce="n")))
    assert response.status_code == 401


def test_expired_token_is_rejected(client, idp):
    token = idp.token("app2-api", exp=int(time.time()) - CLOCK_SKEW_SECONDS - 5)
    assert client.get("/api/whoami", headers=bearer(token)).status_code == 401


def test_small_clock_difference_does_not_fail_a_login(client, idp):
    """Found by live testing: Docker's clock can run behind, which broke 1 login in 12."""
    token = idp.token("app2-api", iat=int(time.time()) + 5)
    assert client.get("/api/whoami", headers=bearer(token)).status_code == 200


def test_clock_allowance_is_limited(client, idp):
    token = idp.token("app2-api", iat=int(time.time()) + CLOCK_SKEW_SECONDS + 60)
    assert client.get("/api/whoami", headers=bearer(token)).status_code == 401


def test_forged_signature_is_rejected(client, idp):
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = idp.token("app2-api", key=attacker)
    assert client.get("/api/whoami", headers=bearer(token)).status_code == 401


def test_writer_role_allows_the_action(client, idp):
    token = idp.token("app2-api", realm_access={"roles": ["writer"]})
    assert client.post("/api/articles", headers=bearer(token)).status_code == 200


def test_missing_role_is_403_not_401(client, idp):
    token = idp.token("app2-api", realm_access={"roles": ["reader"]})
    assert client.post("/api/articles", headers=bearer(token)).status_code == 403


def test_pkce_challenge_is_the_hash_of_the_verifier():
    verifier, challenge = new_pkce_pair()
    assert verifier != challenge
    assert "=" not in challenge
