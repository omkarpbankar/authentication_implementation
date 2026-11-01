"""Entra ID is simulated here, with real signed tokens in Entra's format."""

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from apps.app3_entra import api, main
from apps.app3_entra.settings import settings
from apps.app3_entra.tokens import EntraTokenValidator, groups_are_incomplete, is_app_only
from tests.fake_idp import FakeIdp

HOST = "https://login.test"
TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"
API_ID = "api-client-id"
ISSUER = f"{HOST}/{TENANT}/v2.0"


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
        validator = EntraTokenValidator(HOST, {TENANT}, [API_ID, f"api://{API_ID}"])
        api.app.dependency_overrides[api.get_validator] = lambda: validator
        test_client = TestClient(api.app)
        test_client.router = router
        yield test_client
        api.app.dependency_overrides.clear()


def user_token(idp, **claims):
    defaults = {"tid": TENANT, "ver": "2.0", "scp": "access_as_user", "oid": "o1", "name": "Asha"}
    return idp.token(API_ID, **{**defaults, **claims})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_valid_user_token(client, idp):
    response = client.get("/api/me", headers=bearer(user_token(idp)))
    assert response.status_code == 200
    assert response.json()["tenant"] == TENANT


def test_token_from_a_tenant_not_on_the_list_is_rejected(client, idp):
    token = user_token(idp, tid=OTHER_TENANT)
    assert client.get("/api/me", headers=bearer(token)).status_code == 401


def test_issuer_that_disagrees_with_tid_is_rejected(client, idp):
    """A token cannot claim to be from our tenant if another issuer signed it."""
    other = FakeIdp(f"{HOST}/{OTHER_TENANT}/v2.0", kid=idp.kid)
    token = other.token(API_ID, tid=TENANT, ver="2.0", scp="access_as_user")
    assert client.get("/api/me", headers=bearer(token)).status_code == 401


def test_v1_token_is_rejected(client, idp):
    assert client.get("/api/me", headers=bearer(user_token(idp, ver="1.0"))).status_code == 401


def test_graph_token_is_rejected(client, idp):
    token = idp.token("https://graph.microsoft.com", tid=TENANT, ver="2.0")
    assert client.get("/api/me", headers=bearer(token)).status_code == 401


def test_missing_scope_is_403(client, idp):
    assert client.get("/api/me", headers=bearer(user_token(idp, scp="other"))).status_code == 403


def test_reader_can_read_but_not_write(client, idp):
    headers = bearer(user_token(idp, roles=["Reader"]))
    assert client.get("/api/reports", headers=headers).status_code == 200
    assert client.post("/api/reports", headers=headers).status_code == 403


def test_writer_can_write(client, idp):
    headers = bearer(user_token(idp, roles=["Writer"]))
    assert client.post("/api/reports", headers=headers).status_code == 200


def test_daemon_token_has_roles_and_no_scope(client, idp):
    token = idp.token(API_ID, tid=TENANT, ver="2.0", roles=["Writer"], idtyp="app")
    response = client.get("/api/reports", headers=bearer(token))
    assert response.json()["app_only"] is True


def test_on_behalf_of_exchanges_the_token_and_calls_graph(client, idp):
    class FakeObo:
        def acquire_token_on_behalf_of(self, user_assertion, scopes):
            assert user_assertion
            return {"access_token": "graph-token"}

    api.app.dependency_overrides[api.get_obo_client] = FakeObo
    client.router.get(settings.graph_url).mock(
        return_value=httpx.Response(200, json={"displayName": "Asha", "mail": "a@test"})
    )
    response = client.get("/api/graph-me", headers=bearer(user_token(idp)))
    assert response.json()["display_name"] == "Asha"


def test_failed_on_behalf_of_is_a_502(client, idp):
    class FakeObo:
        def acquire_token_on_behalf_of(self, user_assertion, scopes):
            return {"error": "invalid_grant"}

    api.app.dependency_overrides[api.get_obo_client] = FakeObo
    assert client.get("/api/graph-me", headers=bearer(user_token(idp))).status_code == 502


def test_group_overage_is_detected():
    assert groups_are_incomplete({"_claim_names": {"groups": "src1"}})
    assert groups_are_incomplete({"hasgroups": True})
    assert not groups_are_incomplete({"groups": ["g1"]})


def test_app_only_detection():
    assert is_app_only({"idtyp": "app", "roles": ["Writer"]})
    assert not is_app_only({"scp": "access_as_user"})


class FakeMsal:
    def __init__(self, result=None):
        self.result = result or {
            "access_token": "at",
            "id_token_claims": {"tid": TENANT, "oid": "o1", "name": "Asha"},
        }

    def initiate_auth_code_flow(self, scopes, redirect_uri):
        return {"state": "state-1", "auth_uri": "https://login.test/authorize", "nonce": "n"}

    def acquire_token_by_auth_code_flow(self, flow, params):
        assert flow["state"] == params["state"]
        return self.result


@pytest.fixture
def web():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = main.SessionStore(redis, 3600)
    main.app.dependency_overrides[main.get_store] = lambda: store
    main.app.dependency_overrides[main.get_msal] = FakeMsal
    yield TestClient(main.app, base_url="http://localhost:8003", follow_redirects=False)
    main.app.dependency_overrides.clear()


def test_web_login_uses_oid_and_tid_as_the_identity(web):
    assert web.get("/login").status_code == 303
    assert web.get("/callback", params={"state": "state-1", "code": "c"}).status_code == 303
    assert web.get("/profile").json()["id"] == f"{TENANT}:o1"


def test_web_callback_rejects_a_foreign_state(web):
    web.get("/login")
    assert web.get("/callback", params={"state": "other", "code": "c"}).status_code == 400


def test_unassigned_user_gets_a_403(web):
    denied = FakeMsal({"error": "access_denied", "error_description": "AADSTS50105"})
    main.app.dependency_overrides[main.get_msal] = lambda: denied
    web.get("/login")
    assert web.get("/callback", params={"state": "state-1", "code": "c"}).status_code == 403
    assert web.get("/profile").status_code == 401
