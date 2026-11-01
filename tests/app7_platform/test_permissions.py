"""One test for every role on every route, covering both allowed and denied."""

import uuid

import pytest

from .conftest import OWNER_URL, run_sql

ROLES = ["viewer", "editor", "admin", "owner"]
ALL = set(ROLES)
EDITOR_UP = {"editor", "admin", "owner"}
ADMIN_UP = {"admin", "owner"}

# route name, roles allowed, success status
MATRIX = [
    ("list_projects", ALL, 200),
    ("create_project", EDITOR_UP, 201),
    ("list_documents", ALL, 200),
    ("read_document", ALL, 200),
    ("create_document", EDITOR_UP, 201),
    ("update_others_document", EDITOR_UP, 200),
    ("delete_document", ADMIN_UP, 204),
    ("list_members", ALL, 200),
    ("add_member", ADMIN_UP, 201),
    ("read_audit", ADMIN_UP, 200),
    ("export", {"owner"}, 200),
    ("suspend", {"owner"}, 200),
]


class Scene:
    def __init__(self, h):
        self.h = h
        self.founder = h.person("founder")
        self.slug, self.tenant_id = h.tenant(self.founder)
        self.founder_headers = self.founder.enter(self.slug)
        self.project = h.client.post(
            f"/t/{self.slug}/projects", json={"name": "base"}, headers=self.founder_headers
        ).json()["id"]
        self.document = self.new_document(self.founder_headers)

    def new_document(self, headers, **fields):
        response = self.h.client.post(
            f"/t/{self.slug}/projects/{self.project}/documents",
            json={"title": uuid.uuid4().hex, **fields},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def extra_user(self):
        person = self.h.person("extra")
        self.h.client.get("/me/tenants", headers=person.idp_headers())
        return person.user_id()

    def call(self, name, headers):
        client, slug = self.h.client, self.slug
        document = f"/t/{slug}/documents/{self.document}"
        calls = {
            "list_projects": lambda: client.get(f"/t/{slug}/projects", headers=headers),
            "create_project": lambda: client.post(
                f"/t/{slug}/projects", json={"name": uuid.uuid4().hex}, headers=headers
            ),
            "list_documents": lambda: client.get(f"/t/{slug}/documents", headers=headers),
            "read_document": lambda: client.get(document, headers=headers),
            "create_document": lambda: client.post(
                f"/t/{slug}/projects/{self.project}/documents",
                json={"title": "new"},
                headers=headers,
            ),
            "update_others_document": lambda: client.put(
                document, json={"title": "changed"}, headers=headers
            ),
            "delete_document": lambda: client.delete(document, headers=headers),
            "list_members": lambda: client.get(f"/t/{slug}/members", headers=headers),
            "add_member": lambda: client.post(
                f"/t/{slug}/members",
                json={"user_id": self.extra_user(), "role": "viewer"},
                headers=headers,
            ),
            "read_audit": lambda: client.get(f"/t/{slug}/audit", headers=headers),
            "export": lambda: client.get(f"/t/{slug}/export", headers=headers),
            "suspend": lambda: client.post(f"/t/{slug}/suspend", headers=headers),
        }
        return calls[name]()


@pytest.fixture
def scene(h):
    return Scene(h)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(("route", "allowed", "success"), MATRIX, ids=[row[0] for row in MATRIX])
def test_matrix(h, scene, role, route, allowed, success):
    _, headers = h.member(scene.founder_headers, scene.slug, role)
    response = scene.call(route, headers)
    expected = success if role in allowed else 403
    assert response.status_code == expected, response.text


def test_every_api_route_is_in_the_matrix_or_listed_as_public():
    """Fails when someone adds a tenant route and forgets to test its permissions."""
    from apps.app7_platform.main import app

    tenant_routes = sorted(
        f"{sorted(route.methods)[0]} {route.path}"
        for route in app.routes
        if getattr(route, "path", "").startswith("/t/")
    )
    tested_elsewhere = {
        "DELETE /t/{tenant_slug}",
        "DELETE /t/{tenant_slug}/members/{user_id}",
        "PUT /t/{tenant_slug}/members/{user_id}/role",
    }
    assert len(tenant_routes) == len(MATRIX) + len(tested_elsewhere)


def test_no_token_is_401_on_a_tenant_route(h, scene):
    assert h.client.get(f"/t/{scene.slug}/documents").status_code == 401


def test_viewer_can_edit_their_own_document_but_not_others(h, scene):
    viewer, headers = h.member(scene.founder_headers, scene.slug, "viewer")
    run_sql(
        OWNER_URL,
        "UPDATE documents SET owner_id = :o WHERE id = :d",
        {"o": viewer.user_id(), "d": scene.document},
        tenant=scene.tenant_id,
    )
    url = f"/t/{scene.slug}/documents/{scene.document}"
    assert h.client.put(url, json={"title": "mine"}, headers=headers).status_code == 200

    someone_elses = scene.new_document(scene.founder_headers)
    other_url = f"/t/{scene.slug}/documents/{someone_elses}"
    assert h.client.put(other_url, json={"title": "no"}, headers=headers).status_code == 403


def test_confidential_document_needs_clearance(h, scene):
    secret = scene.new_document(scene.founder_headers, confidential=True)
    url = f"/t/{scene.slug}/documents/{secret}"

    _, no_clearance = h.member(scene.founder_headers, scene.slug, "admin")
    _, cleared = h.member(scene.founder_headers, scene.slug, "viewer", clearance=1)

    # Even an admin gets a 404, because this rule depends on an attribute, not a role.
    assert h.client.get(url, headers=no_clearance).status_code == 404
    assert h.client.get(url, headers=cleared).status_code == 200
    listed = h.client.get(f"/t/{scene.slug}/documents", headers=no_clearance).json()
    assert secret not in [d["id"] for d in listed]


def test_creating_a_confidential_document_needs_clearance(h, scene):
    _, headers = h.member(scene.founder_headers, scene.slug, "editor")
    response = h.client.post(
        f"/t/{scene.slug}/projects/{scene.project}/documents",
        json={"title": "x", "confidential": True},
        headers=headers,
    )
    assert response.status_code == 403


def test_admin_cannot_promote_themselves(h, scene):
    admin, headers = h.member(scene.founder_headers, scene.slug, "admin")
    response = h.client.put(
        f"/t/{scene.slug}/members/{admin.user_id()}/role", json={"role": "owner"}, headers=headers
    )
    assert response.status_code == 403


def test_admin_cannot_grant_owner_to_anyone(h, scene):
    _, headers = h.member(scene.founder_headers, scene.slug, "admin")
    viewer, _ = h.member(scene.founder_headers, scene.slug, "viewer")
    url = f"/t/{scene.slug}/members/{viewer.user_id()}/role"
    assert h.client.put(url, json={"role": "owner"}, headers=headers).status_code == 403
    new = {"user_id": scene.extra_user(), "role": "owner"}
    assert h.client.post(f"/t/{scene.slug}/members", json=new, headers=headers).status_code == 403


def test_admin_cannot_change_or_remove_an_owner(h, scene):
    _, headers = h.member(scene.founder_headers, scene.slug, "admin")
    owner_id = scene.founder.user_id()
    base = f"/t/{scene.slug}/members/{owner_id}"
    assert h.client.put(f"{base}/role", json={"role": "viewer"}, headers=headers).status_code == 403
    assert h.client.delete(base, headers=headers).status_code == 403


def test_last_owner_cannot_be_demoted_or_removed(h, scene):
    second, second_headers = h.member(scene.founder_headers, scene.slug, "owner")
    base = f"/t/{scene.slug}/members/{scene.founder.user_id()}"
    h.client.delete(base, headers=second_headers)

    last = f"/t/{scene.slug}/members/{second.user_id()}"
    _, third_headers = h.member(second_headers, scene.slug, "admin")
    assert h.client.delete(last, headers=third_headers).status_code == 403
    response = h.client.put(f"{last}/role", json={"role": "viewer"}, headers=second_headers)
    assert response.status_code == 403


def test_unknown_role_is_rejected(h, scene):
    response = h.client.post(
        f"/t/{scene.slug}/members",
        json={"user_id": scene.extra_user(), "role": "wizard"},
        headers=scene.founder_headers,
    )
    assert response.status_code == 422


def test_role_change_applies_on_the_next_request(h, scene):
    viewer, headers = h.member(scene.founder_headers, scene.slug, "viewer")
    url = f"/t/{scene.slug}/projects"
    assert h.client.post(url, json={"name": "a"}, headers=headers).status_code == 403
    h.client.put(
        f"{url.replace('projects', 'members')}/{viewer.user_id()}/role",
        json={"role": "editor"},
        headers=scene.founder_headers,
    )
    assert h.client.post(url, json={"name": "a"}, headers=headers).status_code == 201


def test_sensitive_actions_are_audited(h, scene):
    viewer, _ = h.member(scene.founder_headers, scene.slug, "viewer")
    h.client.put(
        f"/t/{scene.slug}/members/{viewer.user_id()}/role",
        json={"role": "editor"},
        headers=scene.founder_headers,
    )
    entries = h.client.get(f"/t/{scene.slug}/audit", headers=scene.founder_headers).json()
    actions = {entry["action"] for entry in entries}
    assert {"member.added", "member.role_changed", "document.created"} <= actions


def test_denied_request_writes_nothing(h, scene):
    _, headers = h.member(scene.founder_headers, scene.slug, "viewer")
    h.client.post(f"/t/{scene.slug}/projects", json={"name": "blocked"}, headers=headers)
    names = [
        p["name"]
        for p in h.client.get(f"/t/{scene.slug}/projects", headers=scene.founder_headers).json()
    ]
    assert "blocked" not in names
