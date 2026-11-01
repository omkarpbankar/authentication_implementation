from urllib.parse import parse_qs, urlsplit

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from apps.app2_oidc import manual_flow
from apps.app2_oidc.oidc import OidcProvider
from apps.app2_oidc.sessions import SessionStore
from tests.fake_idp import FakeIdp

CLIENT_ID = "app2-web"


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def client(idp):
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app = manual_flow.app
    app.dependency_overrides[manual_flow.get_store] = lambda: SessionStore(redis, 3600)
    provider = OidcProvider(idp.issuer)
    app.dependency_overrides[manual_flow.get_provider] = lambda: provider
    yield TestClient(app, base_url="http://localhost:8002", follow_redirects=False)
    app.dependency_overrides.clear()


@pytest.fixture
def mock_idp(idp):
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        yield router


def start_login(client):
    response = client.get("/login")
    assert response.status_code == 303
    return parse_qs(urlsplit(response.headers["location"]).query)


def finish_login(client, mock_idp, idp, query, **id_claims):
    nonce = id_claims.pop("nonce", query["nonce"][0])
    id_token = idp.token(CLIENT_ID, nonce=nonce, preferred_username="asha", **id_claims)
    token_route = mock_idp.post(f"{idp.issuer}/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": idp.token("app2-api"),
                "refresh_token": "refresh-1",
                "id_token": id_token,
                "expires_in": 300,
            },
        )
    )
    response = client.get("/callback", params={"code": "abc", "state": query["state"][0]})
    return response, token_route


def test_login_redirect_uses_pkce_state_and_nonce(client, mock_idp):
    query = start_login(client)
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]
    assert len(query["state"][0]) > 30
    assert len(query["nonce"][0]) > 30


def test_full_login_gives_the_browser_a_cookie_and_no_tokens(client, mock_idp, idp):
    query = start_login(client)
    response, token_route = finish_login(client, mock_idp, idp, query)

    assert response.status_code == 303
    profile = client.get("/profile")
    assert profile.json()["name"] == "asha"
    assert "token" not in profile.text
    assert "code_verifier=" in token_route.calls.last.request.content.decode()


def test_callback_rejects_a_state_from_another_browser(client, mock_idp, idp):
    """This is login CSRF: an attacker's valid state, delivered to a victim's browser."""
    start_login(client)
    response = client.get("/callback", params={"code": "abc", "state": "attackers-state"})
    assert response.status_code == 400
    assert client.get("/profile").status_code == 401


def test_callback_without_the_state_cookie_is_rejected(client, mock_idp, idp):
    query = start_login(client)
    client.cookies.clear()
    response = client.get("/callback", params={"code": "abc", "state": query["state"][0]})
    assert response.status_code == 400


def test_callback_cannot_be_replayed(client, mock_idp, idp):
    query = start_login(client)
    state = query["state"][0]
    finish_login(client, mock_idp, idp, query)

    client.cookies.set(manual_flow.STATE_COOKIE, state)
    response = client.get("/callback", params={"code": "abc", "state": state})
    assert response.status_code == 400


def test_wrong_nonce_is_rejected(client, mock_idp, idp):
    query = start_login(client)
    response, _ = finish_login(client, mock_idp, idp, query, nonce="from-another-login")
    assert response.status_code == 400
    assert client.get("/profile").status_code == 401


def test_id_token_for_another_client_is_rejected(client, mock_idp, idp):
    query = start_login(client)
    mock_idp.post(f"{idp.issuer}/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "x",
                "id_token": idp.token("other-client", nonce=query["nonce"][0]),
                "expires_in": 300,
            },
        )
    )
    response = client.get("/callback", params={"code": "abc", "state": query["state"][0]})
    assert response.status_code == 400


def test_open_redirect_is_blocked(client, mock_idp, idp):
    response = client.get("/login", params={"next": "https://evil.example/"})
    query = parse_qs(urlsplit(response.headers["location"]).query)
    result, _ = finish_login(client, mock_idp, idp, query)
    assert result.headers["location"] == "/"


def test_expired_access_token_refreshes_silently(client, mock_idp, idp):
    query = start_login(client)
    id_token = idp.token(CLIENT_ID, nonce=query["nonce"][0], preferred_username="asha")
    mock_idp.post(f"{idp.issuer}/token").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "access_token": "old",
                    "refresh_token": "r1",
                    "id_token": id_token,
                    "expires_in": 0,
                },
            ),
            httpx.Response(
                200, json={"access_token": "new", "refresh_token": "r2", "expires_in": 300}
            ),
        ]
    )
    client.get("/callback", params={"code": "abc", "state": query["state"][0]})
    assert client.get("/profile").status_code == 200


def test_failed_refresh_ends_the_session(client, mock_idp, idp):
    query = start_login(client)
    id_token = idp.token(CLIENT_ID, nonce=query["nonce"][0], preferred_username="asha")
    mock_idp.post(f"{idp.issuer}/token").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "access_token": "old",
                    "refresh_token": "r1",
                    "id_token": id_token,
                    "expires_in": 0,
                },
            ),
            httpx.Response(400, json={"error": "invalid_grant"}),
        ]
    )
    client.get("/callback", params={"code": "abc", "state": query["state"][0]})
    assert client.get("/profile").status_code == 401
    assert client.get("/profile").status_code == 401


def test_logout_ends_both_sessions(client, mock_idp, idp):
    query = start_login(client)
    finish_login(client, mock_idp, idp, query)

    response = client.post("/logout")
    assert response.headers["location"].startswith(f"{idp.issuer}/logout?")
    assert client.get("/profile").status_code == 401
