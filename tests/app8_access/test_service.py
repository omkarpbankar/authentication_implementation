"""The Access Service against real Postgres, covering the edge cases from the plan."""

import asyncio
import datetime
import uuid

import pytest
from sqlalchemy.exc import DBAPIError

from apps.app8_access.access_service import admin as admin_module
from apps.app8_access.access_service import db as database

from .conftest import APP_URL, OWNER_URL, run_sql


def later(hours=1):
    return (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=hours)).isoformat()


@pytest.fixture
def world(h):
    class World:
        app = h.application()
        tenant = h.tenant()
        admin = tenant.admin()

    return World


def test_first_time_user_is_created_with_no_access(world):
    person = world.tenant.person()
    result = person.evaluate(world.app)
    assert result["decision"] is False
    assert result["context"]["reason_code"] == "NO_APP_ACCESS"
    assert result["context"]["reference_id"]
    assert person.user_id()


def test_grant_gives_access_at_the_tier(world):
    person = world.tenant.person(world.app)
    assert world.admin.grant(person, world.app, "standard").status_code == 200
    result = person.evaluate(world.app)
    assert result["decision"] is True
    assert result["context"]["tier"] == "standard"


def test_app_cannot_ask_about_another_app(h, world):
    other = h.application()
    person = world.tenant.person()
    response = h.client.post(
        "/access/v1/evaluation", json=person.payload(other), headers=world.app.service_headers()
    )
    assert response.status_code == 403


def test_unknown_client_is_refused(h, world):
    token = h.idp.token("access-service", azp="not-a-registered-client")
    person = world.tenant.person()
    response = h.client.post(
        "/access/v1/evaluation",
        json=person.payload(world.app),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_missing_token_is_refused(h, world):
    person = world.tenant.person()
    response = h.client.post("/access/v1/evaluation", json=person.payload(world.app))
    assert response.status_code == 401


def test_token_for_another_audience_is_refused(h, world):
    token = h.idp.token("some-other-service", azp=world.app.client_id)
    person = world.tenant.person()
    response = h.client.post(
        "/access/v1/evaluation",
        json=person.payload(world.app),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_unknown_tenant_is_denied_without_detail(h, world):
    person = world.tenant.person()
    body = person.payload(world.app)
    body["context"]["tenant"] = "no-such-tenant"
    response = h.client.post(
        "/access/v1/evaluation", json=body, headers=world.app.service_headers()
    )
    assert response.json()["decision"] is False


def test_access_in_one_tenant_means_nothing_in_another(h, world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "premium")
    other_tenant = h.tenant()
    person.tenant = other_tenant
    assert person.reason(world.app) == "NO_APP_ACCESS"


def test_email_change_keeps_the_grant(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    person.email = "new-address@test.example"
    assert person.evaluate(world.app)["decision"] is True


def test_new_person_reusing_an_old_email_inherits_nothing(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    newcomer = world.tenant.person()
    newcomer.email = person.email
    assert newcomer.reason(world.app) == "NO_APP_ACCESS"


def test_revoked_user_is_denied_and_the_grant_stays_as_history(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    path = f"/users/{person.user_id()}/grants/{world.app.id}/revoke"
    assert world.admin.post(path, reason="left the team").status_code == 200
    assert person.reason(world.app) == "NO_APP_ACCESS"
    rows = run_sql(
        OWNER_URL,
        "SELECT status FROM user_app_access WHERE user_id = :u",
        {"u": person.user_id()},
        tenant=world.tenant.id,
    )
    assert rows == [{"status": "revoked"}]


def test_suspension_then_resume(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "standard")
    base = f"/users/{person.user_id()}/grants/{world.app.id}"
    world.admin.post(f"{base}/suspend", reason="investigation")
    assert person.reason(world.app) == "ACCESS_SUSPENDED"
    world.admin.post(f"{base}/resume", reason="all clear")
    assert person.evaluate(world.app)["context"]["tier"] == "standard"


def test_tier_upgrade_and_downgrade_apply_on_the_next_check(world):
    person = world.tenant.person(world.app)
    feature = f"{world.app.key}.export"
    world.admin.grant(person, world.app, "basic")
    assert person.reason(world.app, feature) == "TIER_TOO_LOW"
    world.admin.grant(person, world.app, "premium")
    assert person.evaluate(world.app, feature)["decision"] is True
    world.admin.grant(person, world.app, "basic")
    assert person.reason(world.app, feature) == "TIER_TOO_LOW"


def test_future_and_expired_grants(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, starts_at=later(1))
    assert person.reason(world.app) == "ACCESS_EXPIRED"
    world.admin.grant(person, world.app, expires_at=later(-1))
    assert person.reason(world.app) == "ACCESS_EXPIRED"
    world.admin.grant(person, world.app, expires_at=later(1))
    assert person.evaluate(world.app)["decision"] is True


def test_quota_uses_the_live_count(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    feature = f"{world.app.key}.create"
    assert person.evaluate(world.app, feature, usage=49)["decision"] is True
    assert person.reason(world.app, feature, usage=50) == "QUOTA_EXCEEDED"


def test_changing_tier_features_needs_no_code_change(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic")
    feature = f"{world.app.key}.export"
    response = world.admin.client.put(
        f"/admin/v1/applications/{world.app.id}/tiers/basic/features",
        json={"feature": feature, "reason": "promotion"},
        headers=world.admin.headers,
    )
    assert response.status_code == 200
    assert person.evaluate(world.app, feature)["decision"] is True


def test_group_grant_and_leaving_the_group(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic")
    group = world.admin.post("/groups", name=f"team-{uuid.uuid4().hex[:6]}").json()
    client, headers = world.admin.client, world.admin.headers
    client.put(
        f"/admin/v1/groups/{group['id']}/grant",
        json={"application_id": str(world.app.id), "tier": "premium", "reason": "team"},
        headers=headers,
    )
    client.put(f"/admin/v1/groups/{group['id']}/members/{person.user_id()}", headers=headers)
    assert person.evaluate(world.app)["context"]["tier"] == "premium"

    client.delete(f"/admin/v1/groups/{group['id']}/members/{person.user_id()}", headers=headers)
    assert person.evaluate(world.app)["context"]["tier"] == "basic"


def test_suspended_direct_grant_beats_a_group_grant(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic")
    group = world.admin.post("/groups", name=f"team-{uuid.uuid4().hex[:6]}").json()
    client, headers = world.admin.client, world.admin.headers
    client.put(
        f"/admin/v1/groups/{group['id']}/grant",
        json={"application_id": str(world.app.id), "tier": "premium", "reason": "team"},
        headers=headers,
    )
    client.put(f"/admin/v1/groups/{group['id']}/members/{person.user_id()}", headers=headers)
    world.admin.post(
        f"/users/{person.user_id()}/grants/{world.app.id}/suspend", reason="investigation"
    )
    assert person.reason(world.app) == "ACCESS_SUSPENDED"


def set_license(world, tier, seat_limit=None, expires_at=None):
    run_sql(
        OWNER_URL,
        "INSERT INTO tenant_app_licenses VALUES (:t, :a, :r, :s, :e)",
        {
            "t": world.tenant.id,
            "a": world.app.id,
            "r": world.app.tier_ids[tier],
            "s": seat_limit,
            "e": expires_at,
        },
        tenant=world.tenant.id,
    )


def test_tenant_license_caps_the_tier(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "premium")
    set_license(world, "standard")
    assert person.evaluate(world.app)["context"]["tier"] == "standard"


def test_expired_license_denies(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic")
    expired = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
    set_license(world, "premium", expires_at=expired)
    assert person.reason(world.app) == "NO_APP_ACCESS"


def test_seat_limit_refuses_with_a_clear_message(world):
    set_license(world, "premium", seat_limit=1)
    first = world.tenant.person(world.app)
    second = world.tenant.person(world.app)
    assert world.admin.grant(first, world.app).status_code == 200
    response = world.admin.grant(second, world.app)
    assert response.status_code == 409
    assert "seats" in response.text


def test_changing_an_existing_seat_holder_still_works_at_the_limit(world):
    set_license(world, "premium", seat_limit=1)
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic")
    assert world.admin.grant(person, world.app, "standard").status_code == 200


def test_two_admins_cannot_both_take_the_last_seat(world):
    """Runs the real grant code twice in parallel, against real row locks."""
    set_license(world, "premium", seat_limit=1)
    people = [world.tenant.person(world.app) for _ in range(2)]
    admin = admin_module.Admin(world.admin.id, world.tenant.id, "super_admin", None, "subject", 0)

    async def grant(person, user_id):
        change = admin_module.GrantChange(tier="basic", reason="race test")
        async with database.tenant_tx(world.tenant.id) as db:
            await admin_module.set_grant(db, admin, user_id, world.app.id, change)

    async def go():
        return await asyncio.gather(
            *(grant(person, person.user_id()) for person in people), return_exceptions=True
        )

    ids = [person.user_id() for person in people]

    async def run_race():
        return await asyncio.gather(
            *(grant(None, user_id) for user_id in ids), return_exceptions=True
        )

    results = asyncio.run(run_race())
    assert sum(1 for result in results if isinstance(result, Exception)) == 1
    rows = run_sql(
        OWNER_URL,
        "SELECT count(*) AS total FROM user_app_access WHERE application_id = :a",
        {"a": world.app.id},
        tenant=world.tenant.id,
    )
    assert rows[0]["total"] == 1


@pytest.mark.parametrize(
    ("status_value", "reason"),
    [("maintenance", "APP_MAINTENANCE"), ("retired", "APP_RETIRED")],
)
def test_application_status_blocks_everyone(world, status_value, reason):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "premium")
    response = world.admin.client.put(
        f"/admin/v1/applications/{world.app.id}/status",
        json={"status": status_value, "reason": "planned work"},
        headers=world.admin.headers,
    )
    assert response.status_code == 200
    assert person.reason(world.app) == reason


def test_disabled_user_is_denied_even_with_a_grant(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "premium")
    world.admin.post(f"/users/{person.user_id()}/disable", reason="left the company")
    assert person.reason(world.app) == "USER_DISABLED"


def test_suspended_tenant_blocks_everyone(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "premium")
    run_sql(
        OWNER_URL, "UPDATE tenants SET status = 'suspended' WHERE id = :t", {"t": world.tenant.id}
    )
    assert person.reason(world.app) == "TENANT_SUSPENDED"


def test_denials_are_grouped_in_the_audit_log(world):
    person = world.tenant.person()
    first = person.evaluate(world.app)["context"]["reference_id"]
    second = person.evaluate(world.app)["context"]["reference_id"]
    assert first == second
    rows = world.admin.get("/audit", reference=first).json()
    assert [row["action"] for row in rows] == ["access.denied"]


def test_every_change_is_audited_with_its_reason(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic", reason="new starter")
    world.admin.grant(person, world.app, "premium", reason="promoted")
    entry = next(row for row in world.admin.get("/audit").json() if row["reason"] == "promoted")
    assert entry["before"] == {"tier": "basic"}
    assert entry["after"] == {"tier": "premium"}


def test_reason_is_required(world):
    person = world.tenant.person(world.app)
    response = world.admin.grant(person, world.app, reason="")
    assert response.status_code == 422


def test_admin_cannot_change_their_own_access(h, world):
    subject = run_sql(OWNER_URL, "SELECT subject FROM users WHERE id = :u", {"u": world.admin.id})[
        0
    ]["subject"]
    response = world.admin.client.put(
        f"/admin/v1/users/{world.admin.id}/grants/{world.app.id}",
        json={"tier": "premium", "reason": "giving myself access"},
        headers=world.admin.headers,
    )
    assert subject
    assert response.status_code == 403


def test_two_admins_editing_one_grant_get_a_conflict(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "basic")
    detail = world.admin.get(f"/users/{person.user_id()}").json()
    version = next(a for a in detail["applications"] if a["id"] == str(world.app.id))["version"]

    assert (
        world.admin.grant(person, world.app, "standard", expected_version=version).status_code
        == 200
    )
    stale = world.admin.grant(person, world.app, "premium", expected_version=version)
    assert stale.status_code == 409
    assert person.evaluate(world.app)["context"]["tier"] == "standard"


def test_double_submit_applies_once(world):
    person = world.tenant.person(world.app)
    client, admin = world.admin.client, world.admin
    url = f"/admin/v1/users/{person.user_id()}/grants/{world.app.id}"
    headers = {**admin.headers, "Idempotency-Key": uuid.uuid4().hex}
    body = {"tier": "basic", "reason": "double click"}
    assert client.put(url, json=body, headers=headers).status_code == 200
    second = client.put(url, json=body, headers=headers)
    assert second.json()["duplicate"] is True
    entries = [row for row in admin.get("/audit").json() if row["reason"] == "double click"]
    assert len(entries) == 1


def test_admin_api_needs_multi_factor_sign_in(world):
    weak = world.tenant.admin(amr=["pwd"])
    assert weak.get("/whoami").status_code == 403


def test_ordinary_user_token_cannot_use_the_admin_api(h, world):
    token = h.idp.token(
        "access-service", amr=["pwd", "otp"], organization=[world.tenant.slug], sub="plain-user"
    )
    response = h.client.get("/admin/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_admin_in_one_tenant_cannot_touch_another(h, world):
    other_tenant = h.tenant()
    other_admin = other_tenant.admin()
    person = world.tenant.person(world.app)
    assert other_admin.grant(person, world.app).status_code == 404


def test_admin_cannot_see_another_tenants_people(h, world):
    """Found by testing: the shared users table let every admin list every tenant's users."""
    other_admin = h.tenant().admin()
    person = world.tenant.person(world.app)

    assert other_admin.get(f"/users/{person.user_id()}").status_code == 404
    listed = [row["email"] for row in other_admin.get("/users", limit=200).json()]
    assert person.email not in listed
    matrix = [row["email"] for row in other_admin.get("/matrix").json()["users"]]
    assert person.email not in matrix

    text = f"email,app_key,tier\n{person.email},{world.app.key},basic"
    preview = other_admin.post("/bulk/preview", csv=text).json()
    assert preview["rows"][0]["error"] == "Unknown user"


def test_person_in_two_tenants_appears_in_both(h, world):
    person = world.tenant.person(world.app)
    other_tenant = h.tenant()
    person.tenant = other_tenant
    person.evaluate(world.app)
    assert other_tenant.admin().get(f"/users/{person.user_id()}").status_code == 200
    assert world.admin.get(f"/users/{person.user_id()}").status_code == 200


ROLE_RULES = [
    ("super_admin", 200, 200, 200, 200),
    ("helpdesk", 200, 403, 200, 403),
    ("auditor", 200, 403, 403, 200),
]


@pytest.mark.parametrize(("role", "view", "grant", "suspend", "audit"), ROLE_RULES)
def test_admin_role_table(world, role, view, grant, suspend, audit):
    admin = world.tenant.admin(role)
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    assert admin.get("/users").status_code == view
    assert admin.grant(person, world.app, "premium").status_code == grant
    response = admin.post(
        f"/users/{person.user_id()}/grants/{world.app.id}/suspend", reason="testing"
    )
    assert response.status_code == suspend
    assert admin.get("/audit").status_code == audit


def test_app_admin_is_limited_to_their_own_application(h, world):
    other_app = h.application()
    admin = world.tenant.admin("app_admin", application=world.app)
    person = world.tenant.person(world.app)
    assert admin.grant(person, world.app).status_code == 200
    assert admin.grant(person, other_app).status_code == 403
    assert admin.get("/admins").status_code == 403


def test_only_super_admins_manage_applications_and_admins(world):
    helpdesk = world.tenant.admin("helpdesk")
    response = helpdesk.client.put(
        f"/admin/v1/applications/{world.app.id}/status",
        json={"status": "retired", "reason": "nope"},
        headers=helpdesk.headers,
    )
    assert response.status_code == 403
    assert helpdesk.get("/admins").status_code == 403


def test_last_super_admin_cannot_be_removed(world):
    response = world.admin.client.request(
        "DELETE",
        f"/admin/v1/admins/{world.admin.id}",
        json={"reason": "leaving"},
        headers=world.admin.headers,
    )
    assert response.status_code == 409


def test_admin_cannot_promote_themselves(world):
    helpdesk = world.tenant.admin("helpdesk")
    response = helpdesk.client.put(
        f"/admin/v1/admins/{helpdesk.id}",
        json={"role": "super_admin", "reason": "please"},
        headers=helpdesk.headers,
    )
    assert response.status_code == 403


def test_sensitive_admin_change_needs_a_recent_sign_in(world):
    stale = world.tenant.admin(auth_time=1)
    person = world.tenant.person(world.app)
    response = stale.client.put(
        f"/admin/v1/admins/{person.user_id()}",
        json={"role": "auditor", "reason": "new auditor"},
        headers=stale.headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "REAUTH_REQUIRED"


def test_admin_role_removed_mid_session_stops_at_once(world):
    second = world.tenant.admin("auditor")
    assert second.get("/users").status_code == 200
    world.admin.client.request(
        "DELETE",
        f"/admin/v1/admins/{second.id}",
        json={"reason": "moved team"},
        headers=world.admin.headers,
    )
    assert second.get("/users").status_code == 403


def test_tier_with_users_cannot_be_deleted(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "premium")
    response = world.admin.client.request(
        "DELETE",
        f"/admin/v1/applications/{world.app.id}/tiers/premium",
        json={"reason": "tidying up"},
        headers=world.admin.headers,
    )
    assert response.status_code == 409


def test_new_tier_between_two_others_leaves_grants_alone(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, "standard")
    created = world.admin.post(
        f"/applications/{world.app.id}/tiers", key="plus", rank=15, reason="new plan"
    )
    assert created.status_code == 201
    assert person.evaluate(world.app)["context"]["tier"] == "standard"


def csv_for(world, *rows):
    return "email,app_key,tier\n" + "\n".join(
        f"{person.email},{world.app.key},{tier}" for person, tier in rows
    )


def test_bulk_preview_changes_nothing(world):
    person = world.tenant.person(world.app)
    preview = world.admin.post("/bulk/preview", csv=csv_for(world, (person, "basic"))).json()
    assert preview["rows"][0]["change"] == "create"
    assert person.reason(world.app) == "NO_APP_ACCESS"


def test_bulk_is_all_or_nothing(world):
    good = world.tenant.person(world.app)
    text = csv_for(world, (good, "basic")) + "\nnobody@test.example,x,basic"
    response = world.admin.post("/bulk/apply", csv=text)
    assert response.status_code == 422
    assert good.reason(world.app) == "NO_APP_ACCESS"


def test_bulk_upload_twice_changes_nothing_the_second_time(world):
    person = world.tenant.person(world.app)
    text = csv_for(world, (person, "standard"))
    assert world.admin.post("/bulk/apply", csv=text).json()["changed"] == 1
    assert world.admin.post("/bulk/apply", csv=text).json() == {"changed": 0, "unchanged": 1}
    assert person.evaluate(world.app)["context"]["tier"] == "standard"


def test_csv_export_neutralizes_spreadsheet_formulas(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app, reason="=HYPERLINK(evil)")
    text = world.admin.get("/audit.csv").text
    assert "'=HYPERLINK" in text
    assert ",=HYPERLINK" not in text


def request_access(h, world, person, note="please"):
    return h.client.post(
        "/access/v1/requests",
        json={
            "subject": person.payload(world.app)["subject"],
            "tenant": world.tenant.slug,
            "application_id": str(world.app.id),
            "note": note,
        },
        headers=world.app.service_headers(),
    )


def test_request_then_approval_gives_access(h, world):
    person = world.tenant.person()
    assert request_access(h, world, person).status_code == 202
    queue = world.admin.get("/requests").json()
    assert len(queue) == 1
    world.admin.post(f"/requests/{queue[0]['id']}/approve", tier="standard", reason="approved")
    assert person.evaluate(world.app)["context"]["tier"] == "standard"
    assert world.admin.get("/requests").json() == []


def test_repeat_requests_make_one_queue_entry(h, world):
    person = world.tenant.person()
    request_access(h, world, person)
    assert "already" in request_access(h, world, person).text
    assert len(world.admin.get("/requests").json()) == 1


def test_requests_are_rate_limited(h, world):
    person = world.tenant.person()
    codes = [request_access(h, world, person).status_code for _ in range(7)]
    assert codes[-1] == 429


def test_note_length_is_limited(h, world):
    person = world.tenant.person()
    assert request_access(h, world, person, note="x" * 501).status_code == 422


def test_approval_fails_for_a_disabled_user(h, world):
    person = world.tenant.person()
    request_access(h, world, person)
    queue = world.admin.get("/requests").json()
    world.admin.post(f"/users/{person.user_id()}/disable", reason="left")
    response = world.admin.post(f"/requests/{queue[0]['id']}/approve", reason="approved")
    assert response.status_code == 409


def test_admin_cannot_approve_their_own_request(h, world):
    second = world.tenant.admin("app_admin", application=world.app)
    subject = run_sql(OWNER_URL, "SELECT subject FROM users WHERE id = :u", {"u": second.id})[0]
    person = world.tenant.person()
    person.subject = subject["subject"]
    request_access(h, world, person)
    queue = second.get("/requests").json()
    response = second.post(f"/requests/{queue[0]['id']}/approve", reason="myself")
    assert response.status_code == 403


def test_rejected_request_cannot_be_approved_later(h, world):
    person = world.tenant.person()
    request_access(h, world, person)
    request_id = world.admin.get("/requests").json()[0]["id"]
    world.admin.post(f"/requests/{request_id}/reject", reason="not needed")
    response = world.admin.post(f"/requests/{request_id}/approve", reason="changed my mind")
    assert response.status_code == 404


def test_access_review_flags_inactive_users(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    run_sql(
        OWNER_URL,
        "UPDATE users SET last_seen_at = now() - interval '90 days' WHERE id = :u",
        {"u": person.user_id()},
    )
    rows = world.admin.get("/reviews").json()
    assert rows[0]["inactive"] is True
    world.admin.client.post(
        f"/admin/v1/reviews/{rows[0]['id']}/confirm", headers=world.admin.headers
    )
    assert world.admin.get("/reviews").json()[0]["reviewed_at"]


def test_erasure_removes_personal_data_and_keeps_the_audit_trail(world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    user_id = person.user_id()
    world.admin.post(f"/users/{user_id}/erase", reason="erasure request")
    row = run_sql(OWNER_URL, "SELECT email, name FROM users WHERE id = :u", {"u": user_id})[0]
    assert row == {"email": "", "name": ""}
    actions = [entry["action"] for entry in world.admin.get("/audit").json()]
    assert "grant.set" in actions
    assert "user.erased" in actions


def test_changes_bump_the_users_version(h, world):
    person = world.tenant.person(world.app)
    before = asyncio.run(h.redis.get(f"ver:user:{person.subject}"))
    world.admin.grant(person, world.app)
    after = asyncio.run(h.redis.get(f"ver:user:{person.subject}"))
    assert before != after


def test_audit_log_is_append_only_for_the_service(world):
    for statement in ("UPDATE access_audit_log SET reason = 'x'", "DELETE FROM access_audit_log"):
        with pytest.raises(DBAPIError, match="permission denied"):
            run_sql(APP_URL, statement, tenant=world.tenant.id)


def test_row_level_security_hides_other_tenants_grants(h, world):
    person = world.tenant.person(world.app)
    world.admin.grant(person, world.app)
    other = h.tenant()
    assert run_sql(APP_URL, "SELECT * FROM user_app_access", tenant=other.id) == []
    assert run_sql(APP_URL, "SELECT * FROM user_app_access") == []


def test_service_role_cannot_bypass_row_level_security():
    roles = run_sql(
        OWNER_URL, "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'access_app'"
    )
    assert roles == [{"rolsuper": False, "rolbypassrls": False}]
