from urllib.parse import parse_qs, urlsplit

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from apps.app2_oidc.oidc import LOGOUT_EVENT, OidcProvider
from apps.app6_sso import oidc_app, scim
from apps.app6_sso.directory import Directory
from apps.app6_sso.oidc_app import app, get_directory, get_provider, get_store
from apps.app6_sso.settings import settings
from tests.fake_idp import FakeIdp

CLIENT = settings.client_id
AUTH = {"Authorization": f"Bearer {settings.scim_token}"}
SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"


class Harness:
    def __init__(self, client, router, idp):
        self.client = client
        self.router = router
        self.idp = idp

    def log_in(self, email="asha@acme.example", sid="sid-1", name="Asha"):
        response = self.client.get("/login")
        query = parse_qs(urlsplit(response.headers["location"]).query)
        token = self.idp.token(CLIENT, nonce=query["nonce"][0], email=email, sid=sid, name=name)
        self.router.post(f"{self.idp.issuer}/token").mock(
            return_value=httpx.Response(200, json={"access_token": "at", "id_token": token})
        )
        return self.client.get("/callback", params={"code": "c", "state": query["state"][0]})

    def logout_token(self, sid="sid-1", **claims):
        defaults = {"sid": sid, "events": {LOGOUT_EVENT: {}}}
        return self.idp.token(CLIENT, **{**defaults, **claims})


@pytest.fixture
def h():
    idp = FakeIdp()
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        provider = OidcProvider(idp.issuer)
        saved = dict(app.dependency_overrides)
        app.dependency_overrides[get_provider] = lambda: provider
        app.dependency_overrides[get_store] = lambda: oidc_app.SessionStore(redis, 3600)
        app.dependency_overrides[get_directory] = lambda: Directory(redis)
        app.dependency_overrides[scim.get_directory] = lambda: Directory(redis)
        client = TestClient(app, base_url="http://localhost:8006", follow_redirects=False)
        yield Harness(client, router, idp)
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved)


def create_scim_user(h, username="asha@acme.example"):
    body = {"schemas": [SCIM_USER], "userName": username, "displayName": "Asha"}
    return h.client.post("/scim/v2/Users", json=body, headers=AUTH)


def deactivate(h, user_id):
    body = {
        "schemas": [scim.PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    }
    return h.client.patch(f"/scim/v2/Users/{user_id}", json=body, headers=AUTH)


def test_first_login_creates_the_user(h):
    h.log_in()
    user = h.client.get("/profile").json()
    assert user["username"] == "asha@acme.example"
    assert user["source"] == "jit"


def test_later_login_refreshes_details_without_a_new_user(h):
    h.log_in(name="Asha")
    first_id = h.client.get("/profile").json()["id"]
    h.client.cookies.clear()
    h.log_in(name="Asha Rao")
    user = h.client.get("/profile").json()
    assert user["id"] == first_id
    assert user["name"] == "Asha Rao"


def test_home_realm_discovery_routes_by_domain(h):
    known = h.client.post("/start", data={"email": "ravi@globex.example"})
    assert known.status_code == 303
    unknown = h.client.post("/start", data={"email": "someone@unknown.example"})
    assert unknown.status_code == 404


def test_silent_sso_never_shows_a_login_page(h):
    location = h.client.get("/silent").headers["location"]
    assert "prompt=none" in location


def test_silent_sso_with_no_idp_session_returns_quietly(h):
    query = parse_qs(urlsplit(h.client.get("/silent").headers["location"]).query)
    response = h.client.get(
        "/callback", params={"state": query["state"][0], "error": "login_required"}
    )
    assert response.status_code == 303
    assert "silent=failed" in response.headers["location"]


def test_back_channel_logout_ends_the_local_session(h):
    h.log_in(sid="sid-1")
    response = h.client.post("/backchannel-logout", data={"logout_token": h.logout_token()})
    assert response.status_code == 200
    assert h.client.get("/profile").status_code == 401


def test_back_channel_logout_only_touches_that_session(h):
    h.log_in(sid="sid-1")
    h.client.post("/backchannel-logout", data={"logout_token": h.logout_token(sid="other")})
    assert h.client.get("/profile").status_code == 200


def test_logout_token_replay_is_rejected(h):
    h.log_in()
    token = h.logout_token()
    h.client.post("/backchannel-logout", data={"logout_token": token})
    replay = h.client.post("/backchannel-logout", data={"logout_token": token})
    assert replay.status_code == 400


@pytest.mark.parametrize(
    "claims",
    [{"events": {}}, {"nonce": "n"}],
    ids=["ordinary-token-without-the-event", "token-with-a-nonce"],
)
def test_bad_logout_tokens_are_rejected(h, claims):
    h.log_in()
    response = h.client.post("/backchannel-logout", data={"logout_token": h.logout_token(**claims)})
    assert response.status_code == 400
    assert h.client.get("/profile").status_code == 200


def test_forged_logout_token_is_rejected(h):
    h.log_in()
    forger = FakeIdp(h.idp.issuer, kid=h.idp.kid)
    token = forger.token(CLIENT, sid="sid-1", events={LOGOUT_EVENT: {}})
    assert h.client.post("/backchannel-logout", data={"logout_token": token}).status_code == 400
    assert h.client.get("/profile").status_code == 200


def test_scim_needs_a_token(h):
    assert h.client.get("/scim/v2/Users/x").status_code == 401
    bad = {"Authorization": "Bearer wrong"}
    assert h.client.get("/scim/v2/Users/x", headers=bad).status_code == 401


def test_scim_create_then_read(h):
    created = create_scim_user(h)
    assert created.status_code == 201
    user_id = created.json()["id"]
    assert h.client.get(f"/scim/v2/Users/{user_id}", headers=AUTH).json()["active"] is True


def test_scim_duplicate_is_a_409_in_scim_format(h):
    create_scim_user(h)
    response = create_scim_user(h)
    assert response.status_code == 409
    assert scim.ERROR_SCHEMA in response.json()["schemas"]


def test_scim_filter_finds_a_user(h):
    create_scim_user(h)
    response = h.client.get(
        "/scim/v2/Users", params={"filter": 'userName eq "asha@acme.example"'}, headers=AUTH
    )
    assert response.json()["totalResults"] == 1


def test_scim_missing_user_is_a_404(h):
    assert h.client.get("/scim/v2/Users/nope", headers=AUTH).status_code == 404


def test_deactivation_ends_live_sessions_and_blocks_new_ones(h):
    user_id = create_scim_user(h).json()["id"]
    h.log_in()
    assert h.client.get("/profile").status_code == 200

    assert deactivate(h, user_id).json()["active"] is False

    assert h.client.get("/profile").status_code == 401
    assert h.log_in().status_code == 403


def test_entra_style_patch_shape_also_works(h):
    user_id = create_scim_user(h).json()["id"]
    body = {
        "schemas": [scim.PATCH_SCHEMA],
        "Operations": [{"op": "Replace", "value": {"active": "False"}}],
    }
    response = h.client.patch(f"/scim/v2/Users/{user_id}", json=body, headers=AUTH)
    assert response.json()["active"] is False


def test_put_can_deactivate(h):
    user_id = create_scim_user(h).json()["id"]
    h.log_in()
    body = {"schemas": [SCIM_USER], "userName": "asha@acme.example", "active": False}
    assert h.client.put(f"/scim/v2/Users/{user_id}", json=body, headers=AUTH).status_code == 200
    assert h.client.get("/profile").status_code == 401


def test_delete_removes_the_user_and_sessions(h):
    user_id = create_scim_user(h).json()["id"]
    h.log_in()
    assert h.client.delete(f"/scim/v2/Users/{user_id}", headers=AUTH).status_code == 204
    assert h.client.get("/profile").status_code == 401
    assert h.client.get(f"/scim/v2/Users/{user_id}", headers=AUTH).status_code == 404
