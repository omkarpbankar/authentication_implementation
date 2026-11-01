"""The admin panel: sign-in rules, sessions, CSRF, and safe display."""

import asyncio
import time
from urllib.parse import parse_qs, urlsplit

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from apps.app2_oidc.oidc import OidcProvider
from apps.app2_oidc.sessions import SessionStore
from apps.app8_access.access_service.settings import settings
from apps.app8_access.admin_panel import main as panel
from tests.fake_idp import FakeIdp

API = f"{settings.access_service_url}/admin/v1"
WHO = {"role": "super_admin", "actions": ["view", "audit", "manage_admins"], "user_id": "u1"}
USER_ID = "00000000-0000-4000-8000-000000000001"
APP_ID = "10000000-0000-4000-8000-000000000001"


class Scene:
    def __init__(self, client, router, idp, store):
        self.client = client
        self.router = router
        self.idp = idp
        self.store = store

    def session(self, **overrides):
        now = int(time.time())
        data = {
            "email": "admin@test.example",
            "role": "super_admin",
            "actions": WHO["actions"],
            "user_id": "u1",
            "access_token": "admin-token",
            "refresh_token": "refresh-token",
            "id_token": "id-token",
            "expires_at": now + 300,
            "csrf_token": "csrf-value",
            "signed_in_at": now,
            "last_seen_at": now,
            **overrides,
        }
        session_id = asyncio.run(self.store.create(data))
        self.client.cookies.set(panel.SESSION_COOKIE, session_id)
        return session_id

    def login(self, who_status=200, **claims):
        response = self.client.get("/login")
        query = parse_qs(urlsplit(response.headers["location"]).query)
        id_token = self.idp.token(
            panel.CLIENT_ID, nonce=query["nonce"][0], email="admin@test.example", **claims
        )
        self.router.post(f"{self.idp.issuer}/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "at", "id_token": id_token, "expires_in": 300}
            )
        )
        self.router.get(f"{API}/whoami").mock(return_value=httpx.Response(who_status, json=WHO))
        return self.client.get("/callback", params={"code": "c", "state": query["state"][0]})


@pytest.fixture
def s():
    idp = FakeIdp(settings.issuer)
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = SessionStore(redis, panel.TOTAL_LIMIT_SECONDS)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        provider = OidcProvider(idp.issuer)
        panel.app.dependency_overrides[panel.get_provider] = lambda: provider
        panel.app.dependency_overrides[panel.get_store] = lambda: store
        panel.app.dependency_overrides[panel.get_http] = lambda: httpx.AsyncClient()
        client = TestClient(panel.app, base_url=settings.panel_url, follow_redirects=False)
        yield Scene(client, router, idp, store)
        panel.app.dependency_overrides.clear()


def dashboard_data(s):
    s.router.get(f"{API}/dashboard").mock(
        return_value=httpx.Response(
            200, json={"live_grants": 3, "open_requests": 1, "expiring_soon": 0, "recent": []}
        )
    )


def test_signed_out_admin_goes_to_login(s):
    response = s.client.get("/")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_admin_with_mfa_signs_in(s):
    dashboard_data(s)
    assert s.login(amr=["pwd", "otp"]).status_code == 303
    assert "3" in s.client.get("/").text


def test_password_alone_is_refused(s):
    response = s.login(amr=["pwd"])
    assert response.status_code == 403
    assert "Multi-factor" in response.text
    assert panel.SESSION_COOKIE not in s.client.cookies


def test_non_admin_is_refused(s):
    response = s.login(who_status=403, amr=["pwd", "otp"])
    assert response.status_code == 403
    assert "no admin role" in response.text
    assert panel.SESSION_COOKIE not in s.client.cookies


def test_foreign_state_is_refused(s):
    assert s.client.get("/callback", params={"code": "c", "state": "x"}).status_code == 400


def test_force_login_asks_for_a_fresh_sign_in(s):
    location = s.client.get("/login", params={"force": "1"}).headers["location"]
    assert "prompt=login" in location
    assert "max_age=0" in location


def test_idle_session_ends(s):
    s.session(last_seen_at=int(time.time()) - panel.IDLE_LIMIT_SECONDS - 5)
    assert s.client.get("/").status_code == 303


def test_session_has_a_total_limit_even_when_active(s):
    s.session(signed_in_at=int(time.time()) - panel.TOTAL_LIMIT_SECONDS - 5)
    assert s.client.get("/").status_code == 303


def test_expired_access_token_refreshes_quietly(s):
    dashboard_data(s)
    s.session(expires_at=int(time.time()) - 1)
    route = s.router.post(f"{s.idp.issuer}/token").mock(
        return_value=httpx.Response(200, json={"access_token": "new", "expires_in": 300})
    )
    assert s.client.get("/").status_code == 200
    assert route.call_count == 1


def test_failed_refresh_ends_the_session(s):
    s.session(expires_at=int(time.time()) - 1)
    s.router.post(f"{s.idp.issuer}/token").mock(return_value=httpx.Response(400, json={}))
    assert s.client.get("/").status_code == 303


def test_write_without_a_csrf_token_is_refused(s):
    s.session()
    route = s.router.put(f"{API}/users/{USER_ID}/grants/{APP_ID}").mock(
        return_value=httpx.Response(200, json={})
    )
    response = s.client.post(
        f"/users/{USER_ID}/grant",
        data={
            "application_id": APP_ID,
            "tier": "basic",
            "reason": "testing",
            "idempotency_key": "k",
        },
    )
    assert response.status_code == 403
    assert route.call_count == 0


def test_write_with_a_csrf_token_reaches_the_service(s):
    s.session()
    route = s.router.put(f"{API}/users/{USER_ID}/grants/{APP_ID}").mock(
        return_value=httpx.Response(200, json={"tier": "basic"})
    )
    response = s.client.post(
        f"/users/{USER_ID}/grant",
        data={
            "csrf_token": "csrf-value",
            "application_id": APP_ID,
            "tier": "basic",
            "reason": "testing",
            "idempotency_key": "key-1",
        },
    )
    assert response.status_code == 303
    assert route.calls.last.request.headers["idempotency-key"] == "key-1"
    assert route.calls.last.request.headers["authorization"] == "Bearer admin-token"


def test_service_refusal_is_shown_to_the_admin(s):
    s.session()
    s.router.put(f"{API}/users/{USER_ID}/grants/{APP_ID}").mock(
        return_value=httpx.Response(409, json={"detail": "This grant has changed."})
    )
    response = s.client.post(
        f"/users/{USER_ID}/grant",
        data={
            "csrf_token": "csrf-value",
            "application_id": APP_ID,
            "tier": "basic",
            "reason": "testing",
            "idempotency_key": "k",
        },
    )
    assert response.status_code == 409
    assert "This grant has changed." in response.text


def test_reauth_required_sends_the_admin_to_sign_in_again(s):
    s.session()
    s.router.request("PUT", f"{API}/admins/{USER_ID}").mock(
        return_value=httpx.Response(403, json={"detail": "REAUTH_REQUIRED"})
    )
    response = s.client.post(
        "/admins",
        data={
            "csrf_token": "csrf-value",
            "user_id": USER_ID,
            "role": "auditor",
            "reason": "new auditor",
        },
    )
    assert response.status_code == 303
    assert "force=1" in response.headers["location"]


def test_a_users_note_cannot_attack_the_admin(s):
    s.session()
    s.router.get(f"{API}/requests").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "1",
                    "email": "x@test.example",
                    "application": "Notes",
                    "requested_tier": "basic",
                    "note": "<script>steal()</script>",
                }
            ],
        )
    )
    page = s.client.get("/requests").text
    assert "<script>steal" not in page
    assert "&lt;script&gt;" in page


def test_security_headers_are_set(s):
    response = s.client.get("/login")
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("path", "api_path", "payload"),
    [
        ("/users", "/users", []),
        ("/matrix", "/matrix", {"applications": [], "users": []}),
        ("/requests", "/requests", []),
        ("/reviews", "/reviews", []),
        ("/audit", "/audit", []),
    ],
)
def test_screens_render(s, path, api_path, payload):
    s.session()
    s.router.get(f"{API}{api_path}").mock(return_value=httpx.Response(200, json=payload))
    assert s.client.get(path).status_code == 200


def test_screens_needing_several_calls_render(s):
    s.session()
    for api_path in ("/applications", "/groups", "/users", "/admins"):
        s.router.get(f"{API}{api_path}").mock(return_value=httpx.Response(200, json=[]))
    for path in ("/applications", "/groups", "/admins", "/bulk"):
        assert s.client.get(path).status_code == 200


def test_panel_stores_no_rules_of_its_own():
    """A guard against drift: authorization belongs in the Access Service."""
    source = panel.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    assert "super_admin" not in text
    assert "app_admin" not in text
