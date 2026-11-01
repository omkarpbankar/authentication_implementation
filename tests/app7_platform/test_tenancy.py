import datetime
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.app7_platform import main
from apps.app7_platform.identity import CognitoAdapter, EntraAdapter, KeycloakAdapter
from tests.fake_idp import FakeIdp

from .conftest import OWNER_URL, run_sql


def new_doc(h, headers, slug, title="Plan", **fields):
    project = h.client.post(
        f"/t/{slug}/projects", json={"name": uuid.uuid4().hex}, headers=headers
    ).json()
    response = h.client.post(
        f"/t/{slug}/projects/{project['id']}/documents",
        json={"title": title, **fields},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def world(h):
    alice = h.person("alice")
    bob = h.person("bob")
    acme, acme_id = h.tenant(alice, "acme")
    globex, globex_id = h.tenant(bob, "globex")
    return {
        "alice": alice,
        "bob": bob,
        "acme": acme,
        "acme_id": acme_id,
        "globex": globex,
        "globex_id": globex_id,
        "alice_headers": alice.enter(acme),
        "bob_headers": bob.enter(globex),
    }


def test_creator_becomes_owner(h, world):
    tenants = h.client.get("/me/tenants", headers=world["alice"].idp_headers()).json()
    assert [(t["slug"], t["role"]) for t in tenants] == [(world["acme"], "owner")]


def test_token_for_one_tenant_cannot_open_another(h, world):
    response = h.client.get(f"/t/{world['globex']}/documents", headers=world["alice_headers"])
    assert response.status_code == 403


def test_outsider_cannot_get_a_token_for_a_tenant(h, world):
    response = h.client.post(
        "/session", json={"tenant": world["globex"]}, headers=world["alice"].idp_headers()
    )
    assert response.status_code == 403


def test_unknown_and_forbidden_tenants_look_the_same(h, world):
    headers = world["alice"].idp_headers()
    forbidden = h.client.post("/session", json={"tenant": world["globex"]}, headers=headers)
    unknown = h.client.post("/session", json={"tenant": "no-such-tenant"}, headers=headers)
    assert forbidden.status_code == unknown.status_code == 403
    assert forbidden.json() == unknown.json()


def test_another_tenants_document_id_is_not_found(h, world):
    document = new_doc(h, world["bob_headers"], world["globex"], title="Secret")
    response = h.client.get(
        f"/t/{world['acme']}/documents/{document['id']}", headers=world["alice_headers"]
    )
    assert response.status_code == 404


def test_cannot_write_into_another_tenants_project(h, world):
    project = h.client.post(
        f"/t/{world['globex']}/projects", json={"name": "b"}, headers=world["bob_headers"]
    ).json()
    response = h.client.post(
        f"/t/{world['acme']}/projects/{project['id']}/documents",
        json={"title": "x"},
        headers=world["alice_headers"],
    )
    assert response.status_code == 404


def test_cannot_update_or_delete_another_tenants_document(h, world):
    document = new_doc(h, world["bob_headers"], world["globex"])
    url = f"/t/{world['acme']}/documents/{document['id']}"
    headers = world["alice_headers"]
    assert h.client.put(url, json={"title": "x"}, headers=headers).status_code == 404
    assert h.client.delete(url, headers=headers).status_code == 404


def test_member_of_two_tenants_needs_a_token_for_each(h, world):
    person, _ = h.member(world["alice_headers"], world["acme"], "viewer")
    h.client.post(
        f"/t/{world['globex']}/members",
        json={"user_id": person.user_id(), "role": "editor"},
        headers=world["bob_headers"],
    )
    acme_headers = person.enter(world["acme"])
    globex_headers = person.enter(world["globex"])
    assert h.client.get(f"/t/{world['acme']}/documents", headers=acme_headers).status_code == 200
    assert h.client.get(f"/t/{world['globex']}/documents", headers=acme_headers).status_code == 403
    assert (
        h.client.get(f"/t/{world['globex']}/documents", headers=globex_headers).status_code == 200
    )


def test_role_in_one_tenant_gives_nothing_in_another(h, world):
    person, _ = h.member(world["alice_headers"], world["acme"], "admin")
    h.client.post(
        f"/t/{world['globex']}/members",
        json={"user_id": person.user_id(), "role": "viewer"},
        headers=world["bob_headers"],
    )
    headers = person.enter(world["globex"])
    response = h.client.post(f"/t/{world['globex']}/projects", json={"name": "x"}, headers=headers)
    assert response.status_code == 403


def test_removed_member_loses_access_at_once_with_a_live_token(h, world):
    person, headers = h.member(world["alice_headers"], world["acme"], "editor")
    url = f"/t/{world['acme']}/documents"
    assert h.client.get(url, headers=headers).status_code == 200

    h.client.delete(
        f"/t/{world['acme']}/members/{person.user_id()}", headers=world["alice_headers"]
    )
    assert h.client.get(url, headers=headers).status_code == 403


def test_suspended_tenant_is_blocked_at_once_with_a_live_token(h, world):
    url = f"/t/{world['acme']}/documents"
    assert (
        h.client.post(f"/t/{world['acme']}/suspend", headers=world["alice_headers"]).status_code
        == 200
    )
    assert h.client.get(url, headers=world["alice_headers"]).status_code == 403
    session = h.client.post(
        "/session", json={"tenant": world["acme"]}, headers=world["alice"].idp_headers()
    )
    assert session.status_code == 403


def test_owner_can_export(h, world):
    new_doc(h, world["alice_headers"], world["acme"], title="Exported", confidential=True)
    data = h.client.get(f"/t/{world['acme']}/export", headers=world["alice_headers"]).json()
    assert [d["title"] for d in data["documents"]] == ["Exported"]
    assert len(data["members"]) == 1


def test_deleting_a_tenant_removes_its_data_only(h, world):
    new_doc(h, world["alice_headers"], world["acme"])
    kept = new_doc(h, world["bob_headers"], world["globex"], title="Kept")
    response = h.client.delete(f"/t/{world['acme']}", headers=world["alice_headers"])
    assert response.status_code == 204
    assert run_sql(OWNER_URL, "SELECT id FROM tenants WHERE id = :i", {"i": world["acme_id"]}) == []
    found = h.client.get(
        f"/t/{world['globex']}/documents/{kept['id']}", headers=world["bob_headers"]
    )
    assert found.status_code == 200


def test_connection_maps_a_provider_tenant_to_our_tenant(h, world):
    external = f"company-{uuid.uuid4().hex[:8]}"
    run_sql(
        OWNER_URL,
        "INSERT INTO tenant_idp_connections VALUES (:i, :e, :t)",
        {"i": h.idp.issuer, "e": external, "t": world["acme_id"]},
    )
    subject = f"carol-{uuid.uuid4().hex[:8]}"
    token = h.idp.token(
        "app7-platform",
        sub=subject,
        organization=[external],
        realm_access={"roles": ["writer"]},
    )
    response = h.client.post("/session", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["tenant"] == world["acme"]
    assert response.json()["role"] == "editor"


def test_provider_tenant_with_no_connection_gets_nothing(h):
    token = h.idp.token("app7-platform", sub="d", organization=["unknown-company"])
    response = h.client.post("/session", json={}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400


def test_session_cannot_be_forged_with_a_tenant_claim(h, world):
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": main.settings.issuer,
            "aud": main.settings.audience,
            "sub": world["alice"].user_id(),
            "tid": world["globex_id"],
            "exp": int(time.time()) + 60,
        },
        attacker,
        algorithm="RS256",
    )
    response = h.client.get(
        f"/t/{world['globex']}/documents", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


def test_only_verified_domains_are_discovered(h, world):
    verified = f"{uuid.uuid4().hex[:8]}.example"
    unverified = f"{uuid.uuid4().hex[:8]}.example"
    for domain, is_verified in ((verified, True), (unverified, False)):
        run_sql(
            OWNER_URL,
            "INSERT INTO tenant_domains VALUES (:d, :t, :v, true)",
            {"d": domain, "t": world["acme_id"], "v": is_verified},
        )
    found = h.client.post("/discover", json={"email": f"a@{verified}"}).json()
    assert found == {"sso": True, "tenant": world["acme"], "password_allowed": False}
    assert h.client.post("/discover", json={"email": f"a@{unverified}"}).json()["sso"] is False


def test_support_sees_nothing_without_a_grant_and_everything_with_one(h, world):
    new_doc(h, world["alice_headers"], world["acme"], title="Customer doc")
    agent = h.person("support")
    url = f"/support/t/{world['acme']}/documents"
    assert h.client.get(url, headers=agent.idp_headers()).json() == []

    expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30)
    run_sql(
        OWNER_URL,
        "INSERT INTO support_grants VALUES (:t, :u, 'ticket 42', :e)",
        {"t": world["acme_id"], "u": agent.user_id(), "e": expires},
        tenant=world["acme_id"],
    )
    documents = h.client.get(url, headers=agent.idp_headers()).json()
    assert [d["title"] for d in documents] == ["Customer doc"]

    audit = h.client.get(f"/t/{world['acme']}/audit", headers=world["alice_headers"]).json()
    assert "support.viewed" in [entry["action"] for entry in audit]


def test_expired_support_grant_shows_nothing(h, world):
    new_doc(h, world["alice_headers"], world["acme"])
    agent = h.person("support")
    h.client.get("/me/tenants", headers=agent.idp_headers())
    expired = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=1)
    run_sql(
        OWNER_URL,
        "INSERT INTO support_grants VALUES (:t, :u, 'old', :e)",
        {"t": world["acme_id"], "u": agent.user_id(), "e": expired},
        tenant=world["acme_id"],
    )
    url = f"/support/t/{world['acme']}/documents"
    assert h.client.get(url, headers=agent.idp_headers()).json() == []


def test_one_tenants_traffic_cannot_exhaust_another_tenant(h, world, monkeypatch):
    monkeypatch.setattr(main.settings, "tenant_requests_per_minute", 2)
    acme = f"/t/{world['acme']}/documents"
    codes = [h.client.get(acme, headers=world["alice_headers"]).status_code for _ in range(4)]
    assert codes[-1] == 429
    other = h.client.get(f"/t/{world['globex']}/documents", headers=world["bob_headers"])
    assert other.status_code == 200


def test_cors_allows_only_listed_sites(h):
    allowed = h.client.options(
        "/session",
        headers={
            "Origin": "http://localhost:8008",
            "Access-Control-Request-Method": "POST",
        },
    )
    blocked = h.client.options(
        "/session",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:8008"
    assert "access-control-allow-origin" not in blocked.headers


def test_redis_keys_and_file_paths_carry_the_tenant():
    tenant = uuid.uuid4()
    assert main.tenant_key(tenant, "limits") == f"tenant:{tenant}:limits"
    assert main.tenant_file_path(tenant, "a.pdf") == f"tenants/{tenant}/a.pdf"
    with pytest.raises(ValueError, match="filename"):
        main.tenant_file_path(tenant, "../other-tenant/a.pdf")


async def test_each_provider_maps_to_one_identity_shape():
    class FakeEntra:
        async def validate(self, token):
            return {
                "iss": "https://login/t1/v2.0",
                "sub": "s",
                "tid": "t1",
                "oid": "o1",
                "roles": ["Writer"],
                "preferred_username": "a@x",
            }

    entra = await EntraAdapter(FakeEntra(), "https://login/").identity("t")
    assert (entra.subject, entra.external_tenant) == ("t1:o1", "t1")
    assert entra.idp_roles == {"Writer"}

    class FakeProvider:
        issuer = "https://cognito"

    class FakeCognito:
        provider = FakeProvider()

        async def validate_access_token(self, token):
            return {
                "iss": "https://cognito",
                "sub": "c1",
                "tenant": "t2",
                "cognito:groups": ["admin"],
            }

    cognito = await CognitoAdapter(FakeCognito()).identity("t")
    assert (cognito.subject, cognito.external_tenant) == ("c1", "t2")
    assert cognito.idp_roles == {"admin"}


def test_token_from_an_unknown_issuer_is_rejected(h):
    stranger = FakeIdp("https://unknown-idp.test")
    token = stranger.token("app7-platform")
    response = h.client.get("/me/tenants", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_keycloak_adapter_matches_only_its_issuer():
    class Provider:
        issuer = "https://a"

    adapter = KeycloakAdapter(Provider(), "aud")
    assert adapter.matches("https://a")
    assert not adapter.matches("https://b")
