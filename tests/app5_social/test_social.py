from urllib.parse import parse_qs, urlsplit

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from apps.app5_social import main
from apps.app5_social.accounts import Accounts
from apps.app5_social.providers import (
    GITHUB_API,
    GITHUB_TOKEN_URL,
    GitHubAdapter,
    OidcAdapter,
    build_registry,
)
from apps.app5_social.settings import Settings
from tests.fake_idp import FakeIdp


class Harness:
    def __init__(self, client, router, google, microsoft):
        self.client = client
        self.router = router
        self.google = google
        self.microsoft = microsoft

    def log_in(self, provider, idp, subject="u1", email="a@test.example", verified=True, path=None):
        response = (
            self.client.post(path, data={"csrf_token": self.csrf()})
            if path
            else (self.client.get(f"/login/{provider}"))
        )
        query = parse_qs(urlsplit(response.headers["location"]).query)
        token = idp.token(
            f"{provider}-client",
            sub=subject,
            nonce=query["nonce"][0],
            email=email,
            email_verified=verified,
            name="Asha",
        )
        self.router.post(f"{idp.issuer}/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "at", "id_token": token, "refresh_token": "secret-rt"}
            )
        )
        return self.client.get(
            f"/callback/{provider}", params={"code": "c", "state": query["state"][0]}
        )

    def csrf(self):
        return self.client.get("/account").json()["csrf_token"]


@pytest.fixture
def h():
    google = FakeIdp("https://google.test")
    microsoft = FakeIdp("https://microsoft.test")
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    with respx.mock(assert_all_called=False) as router:
        for idp in (google, microsoft):
            router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
                return_value=httpx.Response(200, json=idp.metadata())
            )
            router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        registry = {
            "google": OidcAdapter("google", google.issuer, "google-client", "s"),
            "microsoft": OidcAdapter("microsoft", microsoft.issuer, "microsoft-client", "s"),
            "github": GitHubAdapter("gh", "s"),
        }
        main.app.dependency_overrides[main.get_registry] = lambda: registry
        main.app.dependency_overrides[main.get_accounts] = lambda: Accounts(redis, 3600)
        client = TestClient(main.app, base_url="http://localhost:8005", follow_redirects=False)
        yield Harness(client, router, google, microsoft)
        main.app.dependency_overrides.clear()


def test_new_user_signs_in(h):
    assert h.log_in("google", h.google).status_code == 303
    account = h.client.get("/account").json()
    assert account["logins"] == ["google"]
    assert account["email"] == "a@test.example"


def test_returning_user_gets_the_same_account_even_after_an_email_change(h):
    h.log_in("google", h.google, email="old@test.example")
    first = h.client.get("/account").json()
    h.client.post("/logout")
    h.log_in("google", h.google, email="new@test.example")
    assert h.client.get("/account").json()["logins"] == first["logins"]
    assert h.client.get("/account").json()["email"] == "old@test.example"


def test_matching_verified_email_is_not_merged_automatically(h):
    h.log_in("google", h.google, subject="g1")
    h.client.post("/logout")
    response = h.log_in("microsoft", h.microsoft, subject="m1")
    assert response.status_code == 409
    assert h.client.get("/account").status_code == 401


def test_unverified_email_cannot_claim_or_join_an_account(h):
    """Account pre-hijacking: an attacker gets in first using a victim's unverified email."""
    h.log_in("google", h.google, subject="attacker", email="victim@test.example", verified=False)
    assert h.client.get("/account").json()["email"] == ""
    h.client.post("/logout")

    h.log_in("microsoft", h.microsoft, subject="victim", email="victim@test.example")
    account = h.client.get("/account").json()
    assert account["logins"] == ["microsoft"]
    assert account["email"] == "victim@test.example"


def test_signed_in_user_can_link_a_second_provider(h):
    h.log_in("google", h.google, subject="g1")
    h.log_in("microsoft", h.microsoft, subject="m1", path="/link/microsoft")
    assert h.client.get("/account").json()["logins"] == ["google", "microsoft"]


def test_linked_provider_reaches_the_same_account(h):
    h.log_in("google", h.google, subject="g1")
    h.log_in("microsoft", h.microsoft, subject="m1", path="/link/microsoft")
    h.client.post("/logout")
    h.log_in("microsoft", h.microsoft, subject="m1")
    assert h.client.get("/account").json()["logins"] == ["google", "microsoft"]


def test_login_owned_by_another_account_cannot_be_linked(h):
    h.log_in("microsoft", h.microsoft, subject="m1", email="other@test.example")
    h.client.post("/logout")
    h.log_in("google", h.google, subject="g1")
    response = h.log_in("microsoft", h.microsoft, subject="m1", path="/link/microsoft")
    assert response.status_code == 409


def test_link_needs_a_csrf_token(h):
    h.log_in("google", h.google)
    assert h.client.post("/link/microsoft", data={"csrf_token": "bad"}).status_code == 403


def test_link_needs_a_recent_sign_in(h, monkeypatch):
    h.log_in("google", h.google)
    monkeypatch.setattr(main.settings, "reauth_window_seconds", -1)
    response = h.client.post("/link/microsoft", data={"csrf_token": h.csrf()})
    assert response.status_code == 403
    assert "sign in again" in response.text


def test_last_login_method_cannot_be_removed(h):
    h.log_in("google", h.google)
    response = h.client.post("/unlink/google", data={"csrf_token": h.csrf()})
    assert response.status_code == 409


def test_second_login_method_can_be_removed(h):
    h.log_in("google", h.google, subject="g1")
    h.log_in("microsoft", h.microsoft, subject="m1", path="/link/microsoft")
    assert h.client.post("/unlink/google", data={"csrf_token": h.csrf()}).status_code == 200
    assert h.client.get("/account").json()["logins"] == ["microsoft"]


def test_callback_for_a_different_provider_is_rejected(h):
    response = h.client.get("/login/google")
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    assert (
        h.client.get("/callback/microsoft", params={"code": "c", "state": state}).status_code == 400
    )


def test_foreign_state_is_rejected(h):
    h.client.get("/login/google")
    assert h.client.get("/callback/google", params={"code": "c", "state": "x"}).status_code == 400


def test_unknown_provider_is_a_404(h):
    assert h.client.get("/login/myspace").status_code == 404


def github_flow(h, emails, user=None):
    h.router.post(GITHUB_TOKEN_URL).mock(
        return_value=httpx.Response(200, json={"access_token": "gh-token"})
    )
    h.router.get(f"{GITHUB_API}/user").mock(
        return_value=httpx.Response(200, json=user or {"id": 42, "login": "asha", "name": None})
    )
    h.router.get(f"{GITHUB_API}/user/emails").mock(return_value=httpx.Response(200, json=emails))
    response = h.client.get("/login/github")
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    return h.client.get("/callback/github", params={"code": "c", "state": state})


def test_github_uses_its_api_for_a_hidden_email(h):
    emails = [{"email": "A@Test.Example", "primary": True, "verified": True}]
    assert github_flow(h, emails).status_code == 303
    account = h.client.get("/account").json()
    assert account["email"] == "a@test.example"
    assert account["name"] == "asha"


def test_github_unverified_email_is_not_trusted(h):
    github_flow(h, [{"email": "a@test.example", "primary": True, "verified": False}])
    assert h.client.get("/account").json()["email"] == ""


def test_calendar_token_is_encrypted_and_events_can_be_read(h):
    h.log_in("google", h.google, subject="g1")
    response = h.client.post("/calendar/connect", data={"csrf_token": h.csrf()})
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["access_type"] == ["offline"]
    assert "calendar.readonly" in query["scope"][0]

    token = h.google.token(
        "google-client", sub="g1", nonce=query["nonce"][0], email="a@test.example"
    )
    h.router.post(f"{h.google.issuer}/token").mock(
        return_value=httpx.Response(
            200, json={"access_token": "at", "id_token": token, "refresh_token": "secret-rt"}
        )
    )
    h.client.get("/callback/google", params={"code": "c", "state": query["state"][0]})

    h.router.get(main.CALENDAR_URL).mock(
        return_value=httpx.Response(200, json={"items": [{"summary": "Lecture"}]})
    )
    assert h.client.get("/calendar/events").json()["events"] == ["Lecture"]


def test_calendar_without_a_connection_is_a_404(h):
    h.log_in("google", h.google)
    assert h.client.get("/calendar/events").status_code == 404


def test_providers_appear_only_once_configured():
    assert set(build_registry(Settings(_env_file=None))) == {"keycloak"}
    configured = Settings(_env_file=None, google_client_id="id", github_client_id="id")
    assert set(build_registry(configured)) == {"keycloak", "google", "github"}
