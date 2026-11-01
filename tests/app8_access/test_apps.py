"""The three applications: what users see, and how each feature is enforced."""

import asyncio
import json
import time
from dataclasses import asdict

import fakeredis.aioredis
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from apps.app2_oidc.oidc import OidcProvider
from apps.app2_oidc.sessions import SessionStore
from apps.app8_access.access_client.client import AccessDenied, AccessUnavailable, User
from apps.app8_access.access_client.messages import NOT_AUTHORIZED
from apps.app8_access.access_service.settings import settings
from apps.app8_access.files_app import main as files
from apps.app8_access.notes_app import main as notes
from apps.app8_access.reports_app import main as reports
from tests.fake_idp import FakeIdp

USER = User(subject="user-1", tenant="acme", email="asha@test.example", name="Asha")


class FakeAccess:
    """Stands in for the Access Service, with one chosen tier or denial."""

    def __init__(self, tier="basic", features=None, deny=None, down=False):
        self.tier = tier
        self.features = features or {}
        self.deny = deny
        self.down = down
        self.calls = []
        self.requests = []

    async def check(self, user, feature="", usage=None, fresh=False):
        self.calls.append({"feature": feature, "usage": usage, "fresh": fresh})
        if self.down:
            raise AccessUnavailable
        if self.deny:
            raise AccessDenied(self.deny, "ref123", self.tier)
        if feature and feature not in self.features:
            raise AccessDenied("TIER_TOO_LOW", "ref123", self.tier)
        limit = self.features.get(feature)
        if limit is not None and usage is not None and usage >= limit:
            raise AccessDenied("QUOTA_EXCEEDED", "ref123", self.tier)
        return {"tier": self.tier, "features": self.features}

    async def request_access(self, user, note=""):
        self.requests.append(note)
        return "Your request has been sent to your admin."


class Scene:
    def __init__(self, module, access):
        self.module = module
        self.guard = module.guard
        self.guard.access = access
        self.access = access
        self.guard.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        self.guard.sessions = SessionStore(self.guard.redis, 3600)
        self.client = TestClient(
            module.app, base_url=module.config.base_url, follow_redirects=False
        )

    def sign_in(self, user=USER):
        session_id = asyncio.run(
            self.guard.sessions.create({"user": asdict(user), "id_token": "id-token"})
        )
        self.client.cookies.set(self.module.config.cookie, session_id)


def scene(module, **access):
    return Scene(module, FakeAccess(**access))


NOTES_BASIC = {"notes.read": None, "notes.create": 2}
NOTES_PREMIUM = {
    "notes.read": None,
    "notes.create": None,
    "notes.share": None,
    "notes.export": None,
}


def test_signed_out_user_goes_to_login_and_keeps_the_deep_link():
    s = scene(notes, features=NOTES_BASIC)
    response = s.client.get("/notes/share?tab=1")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/notes/share%3Ftab%3D1"


def test_user_with_no_grant_sees_the_exact_message():
    s = scene(notes, deny="NO_APP_ACCESS")
    s.sign_in()
    response = s.client.get("/")
    assert response.status_code == 403
    assert NOT_AUTHORIZED == (
        "You are not authorized to use this application. Please check with your admin."
    )
    assert NOT_AUTHORIZED in response.text


@pytest.mark.parametrize("module", [notes, reports, files], ids=["notes", "reports", "files"])
def test_every_app_shows_the_same_message(module):
    s = scene(module, deny="NO_APP_ACCESS")
    s.sign_in()
    response = s.client.get("/")
    assert response.status_code == 403
    assert NOT_AUTHORIZED in response.text


def test_denied_page_does_not_redirect_so_there_is_no_login_loop():
    s = scene(notes, deny="NO_APP_ACCESS")
    s.sign_in()
    response = s.client.get("/")
    assert "location" not in response.headers


def test_denied_page_offers_a_request_and_sign_out():
    s = scene(notes, deny="NO_APP_ACCESS")
    s.sign_in()
    page = s.client.get("/").text
    assert 'action="/request-access"' in page
    assert 'action="/logout"' in page
    assert "ref123" in page
    assert "asha@test.example" in page


def test_denied_page_names_only_this_application():
    s = scene(notes, deny="NO_APP_ACCESS")
    s.sign_in()
    page = s.client.get("/").text
    assert "Reports" not in page
    assert "Files" not in page


@pytest.mark.parametrize(
    ("reason", "status_code", "text"),
    [
        ("USER_DISABLED", 403, "account is disabled"),
        ("TENANT_SUSPENDED", 403, "organization"),
        ("APP_MAINTENANCE", 503, "temporarily unavailable"),
        ("APP_RETIRED", 410, "no longer available"),
        ("ACCESS_SUSPENDED", 403, "access is suspended"),
        ("ACCESS_EXPIRED", 403, "access has expired"),
    ],
)
def test_each_reason_has_its_own_message(reason, status_code, text):
    s = scene(notes, deny=reason)
    s.sign_in()
    response = s.client.get("/")
    assert response.status_code == status_code
    assert text in response.text


def test_disabled_user_is_not_offered_a_request():
    s = scene(notes, deny="USER_DISABLED")
    s.sign_in()
    assert "request-access" not in s.client.get("/").text


def test_outage_says_unavailable_and_never_not_authorized():
    s = scene(notes, down=True)
    s.sign_in()
    response = s.client.get("/")
    assert response.status_code == 503
    assert "temporarily unavailable" in response.text
    assert "not authorized" not in response.text


def test_api_clients_get_problem_details():
    s = scene(notes, deny="NO_APP_ACCESS")
    s.sign_in()
    response = s.client.get("/", headers={"Accept": "application/json"})
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["reason_code"] == "NO_APP_ACCESS"
    assert body["reference_id"] == "ref123"


def test_api_client_without_a_session_gets_401_not_a_redirect():
    s = scene(notes, features=NOTES_BASIC)
    response = s.client.get("/notes/share", headers={"Accept": "application/json"})
    assert response.status_code == 401


def test_protected_pages_are_not_stored_by_the_browser():
    s = scene(notes, features=NOTES_BASIC)
    s.sign_in()
    assert s.client.get("/").headers["cache-control"] == "no-store"


def test_request_access_reaches_the_service():
    s = scene(notes, deny="NO_APP_ACCESS")
    s.sign_in()
    response = s.client.post("/request-access", data={"note": "I joined the team"})
    assert response.status_code == 202
    assert s.access.requests == ["I joined the team"]


def test_notes_show_the_plan():
    s = scene(notes, tier="premium", features=NOTES_PREMIUM)
    s.sign_in()
    assert "Premium" in s.client.get("/").text


def test_stored_note_is_escaped():
    s = scene(notes, features=NOTES_BASIC)
    s.sign_in()
    s.client.post("/notes", data={"text": "<script>alert(1)</script>"})
    page = s.client.get("/").text
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page


def test_notes_quota_uses_the_live_count_and_keeps_existing_notes():
    s = scene(notes, features=NOTES_BASIC)
    s.sign_in()
    assert s.client.post("/notes", data={"text": "one"}).status_code == 303
    assert s.client.post("/notes", data={"text": "two"}).status_code == 303
    blocked = s.client.post("/notes", data={"text": "three"})
    assert blocked.status_code == 403
    assert "plan limit" in blocked.text
    assert "two" in s.client.get("/").text


def test_basic_plan_cannot_export():
    s = scene(notes, features=NOTES_BASIC)
    s.sign_in()
    response = s.client.get("/notes/export")
    assert response.status_code == 403
    assert "not included in your Basic plan" in response.text


def test_export_rechecks_access_before_delivery():
    s = scene(notes, tier="premium", features=NOTES_PREMIUM)
    s.sign_in()
    assert s.client.get("/notes/export").status_code == 200
    assert s.access.calls[-1] == {"feature": "notes.export", "usage": None, "fresh": True}


def test_reports_csv_needs_standard():
    s = scene(reports, features={"reports.view": None})
    s.sign_in()
    assert s.client.get("/reports/export.csv").status_code == 403
    s.access.features = {"reports.view": None, "reports.export_csv": None}
    assert s.client.get("/reports/export.csv").status_code == 200


def test_scheduled_report_is_skipped_for_a_revoked_user():
    s = scene(reports, features={"reports.schedule": None})
    s.sign_in()
    s.client.get("/reports/schedule")
    assert asyncio.run(reports.run_scheduled_reports()) == {"sent": 1, "skipped": 0}

    s.access.deny = "NO_APP_ACCESS"
    assert asyncio.run(reports.run_scheduled_reports()) == {"sent": 0, "skipped": 1}
    s.access.deny = None
    assert asyncio.run(reports.run_scheduled_reports()) == {"sent": 0, "skipped": 0}


def test_scheduled_job_stores_no_token():
    s = scene(reports, features={"reports.schedule": None})
    s.sign_in()
    s.client.get("/reports/schedule")
    stored = asyncio.run(s.guard.redis.smembers(reports.SCHEDULE_KEY))
    assert "token" not in json.loads(next(iter(stored)))


def test_websocket_closes_when_access_ends(monkeypatch):
    monkeypatch.setattr(reports, "RECHECK_SECONDS", 0)
    s = scene(reports, features={"reports.view": None})
    s.sign_in()
    with s.client.websocket_connect("/reports/live") as socket:
        assert socket.receive_json() == {"update": "ok"}
        s.access.deny = "NO_APP_ACCESS"
        with pytest.raises(WebSocketDisconnect):
            # Updates sent before the denial are still queued, so keep reading until it closes.
            for _ in range(1_000_000):
                socket.receive_json()


def test_websocket_refuses_a_signed_out_user():
    s = scene(reports, features={"reports.view": None})
    with pytest.raises(WebSocketDisconnect), s.client.websocket_connect("/reports/live"):
        pass


FILES_BASIC = {"files.storage_mb": 100}
FILES_PREMIUM = {"files.storage_mb": 50000, "files.folders": None, "files.share_links": None}


def test_storage_limit_includes_the_new_upload():
    s = scene(files, features=FILES_BASIC)
    s.sign_in()
    assert s.client.post("/upload", data={"size_mb": 90}).status_code == 200
    assert s.client.post("/upload", data={"size_mb": 20}).status_code == 403
    assert s.client.post("/upload", data={"size_mb": 10}).status_code == 200


def test_folders_need_standard():
    s = scene(files, features=FILES_BASIC)
    s.sign_in()
    assert s.client.post("/folders").status_code == 403


def share_link(s, name="a.pdf"):
    return s.client.post("/share-links", data={"name": name}).json()["url"]


def test_share_link_works_for_premium():
    s = scene(files, tier="premium", features=FILES_PREMIUM)
    s.sign_in()
    assert s.client.get(share_link(s)).json() == {"file": "a.pdf"}


def test_share_link_stops_when_access_ends():
    s = scene(files, tier="premium", features=FILES_PREMIUM)
    s.sign_in()
    url = share_link(s)
    s.access.deny = "NO_APP_ACCESS"
    assert s.client.get(url).status_code == 403


def test_tampered_share_link_is_refused():
    s = scene(files, tier="premium", features=FILES_PREMIUM)
    s.sign_in()
    url = share_link(s).replace("a.pdf", "secret.pdf")
    assert s.client.get(url).status_code == 403


def test_expired_share_link_is_refused():
    s = scene(files, tier="premium", features=FILES_PREMIUM)
    s.sign_in()
    expires = int(time.time()) - 5
    signature = files.sign_link(USER, "a.pdf", expires)
    url = f"/shared/a.pdf?expires={expires}&sig={signature}"
    assert s.client.get(url).status_code == 403


@pytest.fixture
def idp_scene():
    idp = FakeIdp(settings.issuer)
    s = scene(notes, features=NOTES_BASIC)
    s.guard.provider = OidcProvider(idp.issuer)
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{idp.issuer}/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=idp.metadata())
        )
        router.get(f"{idp.issuer}/jwks").mock(return_value=httpx.Response(200, json=idp.jwks()))
        s.idp = idp
        yield s


def test_token_for_notes_works_on_notes(idp_scene):
    token = idp_scene.idp.token("notes-app", organization=["acme"])
    response = idp_scene.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_token_for_reports_is_rejected_by_notes(idp_scene):
    token = idp_scene.idp.token("reports-app", organization=["acme"])
    response = idp_scene.client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["reason_code"] == "WRONG_AUDIENCE"


def test_login_ignores_a_next_address_on_another_site(idp_scene):
    response = idp_scene.client.get("/login", params={"next": "https://evil.example/"})
    assert response.status_code == 303
    attempts = asyncio.run(idp_scene.guard.redis.keys("login:*"))
    stored = asyncio.run(idp_scene.guard.redis.get(attempts[0]))
    assert json.loads(stored)["next"] == "/"


def test_application_id_comes_from_configuration_not_the_request():
    assert notes.config.application_id == notes.guard.config.application_id
    routes = notes.app.openapi()["paths"]
    parameters = json.dumps(routes)
    assert "application_id" not in parameters
