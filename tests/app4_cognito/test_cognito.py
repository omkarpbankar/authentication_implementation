"""Cognito is simulated here, with real signed tokens in Cognito's format."""

import base64
import hashlib
import hmac
import importlib.util
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import boto3
import fakeredis.aioredis
import httpx
import jwt
import pytest
import respx
from botocore.stub import Stubber
from fastapi.testclient import TestClient

from apps.app2_oidc.oidc import OidcProvider
from apps.app4_cognito import main
from apps.app4_cognito.custom_ui import CognitoUsers, SignInFailed, secret_hash
from apps.app4_cognito.settings import settings
from tests.fake_idp import FakeIdp

ISSUER = settings.issuer


@pytest.fixture
def idp():
    return FakeIdp(ISSUER)


@pytest.fixture
def client(idp):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{ISSUER}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{ISSUER}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        provider = OidcProvider(ISSUER)
        redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        main.app.dependency_overrides[main.get_provider] = lambda: provider
        main.app.dependency_overrides[main.get_store] = lambda: main.SessionStore(redis, 3600)
        test_client = TestClient(main.app, base_url="http://localhost:8004", follow_redirects=False)
        test_client.router = router
        yield test_client
        main.app.dependency_overrides.clear()


def access_token(idp, **claims):
    """Cognito access tokens have client_id and no aud, so this removes the usual claim."""
    defaults = {"client_id": settings.client_id, "token_use": "access", "scope": "openid"}
    payload = {**defaults, **claims}
    return jwt.encode(
        {"iss": ISSUER, "sub": "user-1", "exp": 4_102_444_800, **payload},
        idp.key,
        algorithm="RS256",
        headers={"kid": idp.kid},
    )


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_access_token_without_aud_is_accepted(client, idp):
    token = access_token(idp, **{"cognito:groups": ["member"], "plan": "basic"})
    response = client.get("/api/members", headers=bearer(token))
    assert response.status_code == 200
    assert response.json()["plan"] == "basic"


def test_id_token_cannot_call_the_api(client, idp):
    token = access_token(idp, token_use="id", **{"cognito:groups": ["member"]})
    assert client.get("/api/members", headers=bearer(token)).status_code == 401


def test_token_for_another_app_client_is_rejected(client, idp):
    token = access_token(idp, client_id="some-other-client")
    assert client.get("/api/members", headers=bearer(token)).status_code == 401


def test_token_from_another_pool_is_rejected(client, idp):
    other = FakeIdp("https://cognito-idp.us-east-1.amazonaws.com/other", kid=idp.kid)
    token = access_token(other)
    assert client.get("/api/members", headers=bearer(token)).status_code == 401


def test_group_rules(client, idp):
    member = bearer(access_token(idp, **{"cognito:groups": ["member"]}))
    admin = bearer(access_token(idp, **{"cognito:groups": ["admin"]}))
    nobody = bearer(access_token(idp))
    assert client.delete("/api/members/5", headers=member).status_code == 403
    assert client.delete("/api/members/5", headers=admin).status_code == 200
    assert client.get("/api/members", headers=nobody).status_code == 403


def test_machine_client_uses_custom_scope(client, idp):
    allowed = access_token(idp, client_id=settings.m2m_client_id, scope="orders/read")
    denied = access_token(idp, client_id=settings.m2m_client_id, scope="other/read")
    assert client.get("/api/orders", headers=bearer(allowed)).status_code == 200
    assert client.get("/api/orders", headers=bearer(denied)).status_code == 403


def test_logout_uses_cognitos_own_endpoint(client):
    location = client.post("/logout").headers["location"]
    assert location.startswith(f"{settings.domain}/logout?")
    assert "client_id=" in location


def test_managed_login_rejects_a_foreign_state(client):
    assert client.get("/callback", params={"code": "c", "state": "x"}).status_code == 400


def test_managed_login_full_flow(client, idp):
    query = parse_qs(urlsplit(client.get("/login").headers["location"]).query)
    id_token = idp.token(
        settings.client_id, token_use="id", email="a@test", nonce=query["nonce"][0]
    )
    client.router.post(f"{ISSUER}/token").mock(
        return_value=httpx.Response(200, json={"access_token": "at", "id_token": id_token})
    )
    response = client.get("/callback", params={"code": "c", "state": query["state"][0]})
    assert response.status_code == 303
    assert client.get("/profile").json()["email"] == "a@test"


def stubbed_users(secret="client-secret"):
    raw = boto3.client(
        "cognito-idp",
        region_name="ap-south-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    return CognitoUsers("client-id", secret, "ap-south-1", client=raw), Stubber(raw)


def test_secret_hash_matches_awss_formula():
    expected = base64.b64encode(
        hmac.new(b"secret", b"userclient", hashlib.sha256).digest()
    ).decode()
    assert secret_hash("user", "client", "secret") == expected


def test_sign_up_hides_existing_accounts():
    users, stub = stubbed_users()
    stub.add_client_error("sign_up", "UsernameExistsException")
    with stub:
        users.sign_up("taken@test", "correct-horse-battery")


def test_wrong_password_raises_one_generic_error():
    users, stub = stubbed_users()
    stub.add_client_error("initiate_auth", "NotAuthorizedException")
    with stub, pytest.raises(SignInFailed, match="Invalid email or password"):
        users.sign_in("a@test", "wrong")


def test_sign_in_sends_the_secret_hash():
    users, stub = stubbed_users()
    stub.add_response(
        "initiate_auth",
        {"AuthenticationResult": {"AccessToken": "a", "IdToken": "i"}},
        {
            "ClientId": "client-id",
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {
                "USERNAME": "a@test",
                "PASSWORD": "correct-horse-battery",
                "SECRET_HASH": secret_hash("a@test", "client-id", "client-secret"),
            },
        },
    )
    with stub:
        assert users.sign_in("a@test", "correct-horse-battery")["AccessToken"] == "a"


def load_lambda():
    path = Path("infra/lambda/pre_token.py")
    spec = importlib.util.spec_from_file_location("pre_token", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("groups", "plan"), [(["admin"], "premium"), (["member"], "basic"), (None, "basic")]
)
def test_lambda_adds_the_plan_claim(groups, plan):
    event = {"request": {"groupConfiguration": {"groupsToOverride": groups}}}
    result = load_lambda().handler(event, None)
    details = result["response"]["claimsAndScopeOverrideDetails"]
    assert details["accessTokenGeneration"]["claimsToAddOrOverride"]["plan"] == plan
