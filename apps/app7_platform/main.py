"""App 7: a multi-tenant document platform, with row-level security and permissions.

Run once:  uv run python scripts/setup_platform_db.py
Run:       uv run uvicorn apps.app7_platform.main:app --port 8008
"""

import re
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from apps.app2_oidc.oidc import TokenError
from apps.app7_platform import queries
from apps.app7_platform.auth import (
    Credentials,
    KeyRingDep,
    Principal,
    TenantContext,
    create_tenant_token,
    get_verifier,
    require_permission,
    unauthorized,
)
from apps.app7_platform.database import support_engine, tenant_transaction
from apps.app7_platform.identity import Identity, TokenVerifier
from apps.app7_platform.settings import settings
from apps.shared.hardening import apply_hardening

app = FastAPI(title="App 7: multi-tenant platform")
apply_hardening(app)
# A strict list, with no wildcards. Browsers then refuse calls from any other website.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")


class NewTenant(BaseModel):
    slug: str
    name: str


class SessionRequest(BaseModel):
    tenant: str | None = None


class NewProject(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class NewDocument(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = ""
    confidential: bool = False


class DocumentUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = ""


class RoleChange(BaseModel):
    role: str


class NewMember(BaseModel):
    user_id: UUID
    role: str = "viewer"
    clearance: int = 0


class EmailLookup(BaseModel):
    email: str


async def current_identity(
    credentials: Credentials,
    verifier: Annotated[TokenVerifier, Depends(get_verifier)],
) -> Identity:
    if credentials is None:
        raise unauthorized()
    try:
        return await verifier.identity(credentials.credentials)
    except TokenError as exc:
        raise unauthorized() from exc


IdentityDep = Annotated[Identity, Depends(current_identity)]


def tenant_key(tenant_id: UUID, name: str) -> str:
    """Redis has no row-level security, so every key carries its tenant."""
    return f"tenant:{tenant_id}:{name}"


def tenant_file_path(tenant_id: UUID, filename: str) -> str:
    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError("Invalid filename")
    return f"tenants/{tenant_id}/{filename}"


def initial_role(identity: Identity) -> str:
    roles = [settings.idp_role_map[r] for r in identity.idp_roles if r in settings.idp_role_map]
    return "editor" if "editor" in roles else "viewer"


@app.post("/tenants", status_code=status.HTTP_201_CREATED)
async def create_tenant(body: NewTenant, identity: IdentityDep) -> dict:
    if not SLUG_PATTERN.fullmatch(body.slug):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid tenant slug")
    async with tenant_transaction() as db:
        user_id = await queries.find_or_create_user(db, identity)
    try:
        async with tenant_transaction() as db:
            tenant = await queries.tenant_by_slug(db, body.slug)
            if tenant:
                raise HTTPException(status.HTTP_409_CONFLICT, "That name is taken")
            row = await db.execute(
                text("INSERT INTO tenants (slug, name) VALUES (:s, :n) RETURNING id"),
                {"s": body.slug, "n": body.name},
            )
            tenant_id = row.scalar_one()
        async with tenant_transaction(tenant_id, user_id) as db:
            await queries.add_membership(db, tenant_id, user_id, "owner", clearance=1)
            await queries.audit(db, tenant_id, user_id, "tenant.created", body.slug)
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "That name is taken") from exc
    return {"id": tenant_id, "slug": body.slug}


@app.get("/me/tenants")
async def my_tenants(identity: IdentityDep) -> list[dict]:
    async with tenant_transaction() as db:
        user_id = await queries.find_or_create_user(db, identity)
    async with tenant_transaction(user_id=user_id) as db:
        return await queries.memberships_of(db)


@app.post("/session")
async def open_session(body: SessionRequest, identity: IdentityDep, ring: KeyRingDep) -> dict:
    """Swap a provider's token for a short-lived token tied to one tenant."""
    async with tenant_transaction() as db:
        user_id = await queries.find_or_create_user(db, identity)
        connected_tenant = await queries.tenant_for_connection(db, identity)
        wanted = await queries.tenant_by_slug(db, body.tenant) if body.tenant else None

    if body.tenant and wanted is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this tenant")

    # A company's own login places its users in that company's tenant.
    if connected_tenant and (wanted is None or wanted["id"] == connected_tenant):
        async with tenant_transaction(connected_tenant, user_id) as db:
            await queries.add_membership(db, connected_tenant, user_id, initial_role(identity))
            wanted = await queries.tenant_by_id(db, connected_tenant)

    if wanted is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a tenant")
    if wanted["status"] != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This organization is suspended")

    async with tenant_transaction(wanted["id"], user_id) as db:
        member = await queries.membership(db, wanted["id"], user_id)
        if member is None:
            # A tenant name supplied by the client proves nothing until membership is checked.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this tenant")
        await queries.audit(db, wanted["id"], user_id, "session.opened")

    return {
        "access_token": create_tenant_token(ring, user_id, wanted["id"]),
        "tenant": wanted["slug"],
        "role": member["role"],
    }


@app.post("/discover")
async def discover(body: EmailLookup) -> dict:
    """Home realm discovery. Only verified domains count, or anyone could claim gmail.com."""
    domain = body.email.rpartition("@")[2].lower()
    async with tenant_transaction() as db:
        found = await queries.discover_domain(db, domain)
    if found is None:
        return {"sso": False, "password_allowed": True}
    return {"sso": True, "tenant": found["slug"], "password_allowed": not found["sso_enforced"]}


def allowed(permission: str):
    return Depends(require_permission(permission))


Readable = Annotated[TenantContext, allowed("document:read")]
ProjectReader = Annotated[TenantContext, allowed("project:read")]
ProjectWriter = Annotated[TenantContext, allowed("project:write")]
Deleter = Annotated[TenantContext, allowed("document:delete")]
MemberReader = Annotated[TenantContext, allowed("member:read")]
MemberManager = Annotated[TenantContext, allowed("member:manage")]
AuditReader = Annotated[TenantContext, allowed("audit:read")]
OrgManager = Annotated[TenantContext, allowed("org:manage")]


@app.get("/t/{tenant_slug}/projects")
async def list_projects(context: ProjectReader) -> list[dict]:
    return await queries.list_projects(context[0])


@app.post("/t/{tenant_slug}/projects", status_code=status.HTTP_201_CREATED)
async def create_project(body: NewProject, context: ProjectWriter) -> dict:
    db, principal = context
    try:
        async with db.begin_nested():
            return await queries.create_project(db, principal.tenant_id, body.name)
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Project name already used") from exc


@app.get("/t/{tenant_slug}/documents")
async def list_documents(context: Readable) -> list[dict]:
    db, principal = context
    return await queries.list_documents(db, principal.clearance)


@app.post("/t/{tenant_slug}/projects/{project_id}/documents", status_code=status.HTTP_201_CREATED)
async def create_document(project_id: UUID, body: NewDocument, context: ProjectWriter) -> dict:
    db, principal = context
    if body.confidential and principal.clearance < 1:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Clearance required")
    try:
        async with db.begin_nested():
            created = await queries.create_document(
                db,
                principal.tenant_id,
                project_id,
                principal.user_id,
                body.title,
                body.body,
                body.confidential,
            )
    except IntegrityError as exc:
        # Also what happens for another tenant's project, thanks to the composite foreign key.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found") from exc
    await queries.audit(db, principal.tenant_id, principal.user_id, "document.created", body.title)
    return created


async def readable_document(db, principal: Principal, document_id: UUID) -> dict:
    found = await queries.document(db, document_id)
    # The same 404 for "missing" and "not allowed", so IDs reveal nothing about what exists.
    if found is None or (found["confidential"] and principal.clearance < 1):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Document not found")
    return found


@app.get("/t/{tenant_slug}/documents/{document_id}")
async def read_document(document_id: UUID, context: Readable) -> dict:
    db, principal = context
    return await readable_document(db, principal, document_id)


@app.put("/t/{tenant_slug}/documents/{document_id}")
async def update_document(document_id: UUID, body: DocumentUpdate, context: Readable) -> dict:
    db, principal = context
    found = await readable_document(db, principal, document_id)
    is_owner = found["owner_id"] == principal.user_id and principal.can("document:write_own")
    if not (principal.can("document:write") or is_owner):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot edit this document")
    await queries.update_document(db, document_id, body.title, body.body)
    await queries.audit(db, principal.tenant_id, principal.user_id, "document.updated", body.title)
    return {"updated": True}


@app.delete("/t/{tenant_slug}/documents/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(document_id: UUID, context: Deleter) -> None:
    db, principal = context
    await readable_document(db, principal, document_id)
    await queries.delete_document(db, document_id)
    await queries.audit(db, principal.tenant_id, principal.user_id, "document.deleted")


@app.get("/t/{tenant_slug}/members")
async def list_members(context: MemberReader) -> list[dict]:
    return await queries.list_members(context[0])


async def rank_of(db, role: str) -> int:
    rank = await queries.role_rank(db, role)
    if rank is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown role")
    return rank


@app.post("/t/{tenant_slug}/members", status_code=status.HTTP_201_CREATED)
async def add_member(body: NewMember, context: MemberManager) -> dict:
    db, principal = context
    if await rank_of(db, body.role) > principal.rank:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot grant a role above your own")
    try:
        async with db.begin_nested():
            await queries.add_membership(
                db, principal.tenant_id, body.user_id, body.role, body.clearance
            )
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found") from exc
    await queries.audit(db, principal.tenant_id, principal.user_id, "member.added", body.role)
    return {"added": True}


@app.put("/t/{tenant_slug}/members/{user_id}/role")
async def change_role(user_id: UUID, body: RoleChange, context: MemberManager) -> dict:
    db, principal = context
    # Without this, an admin could promote themselves or demote their way around a limit.
    if user_id == principal.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot change your own role")

    new_rank = await rank_of(db, body.role)
    target = await queries.membership(db, principal.tenant_id, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    if new_rank > principal.rank or target["rank"] > principal.rank:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "That is above your own role")
    if target["role"] == "owner" and body.role != "owner" and await queries.owner_count(db) == 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "A tenant must keep at least one owner")

    await queries.set_role(db, user_id, body.role)
    await queries.audit(
        db, principal.tenant_id, principal.user_id, "member.role_changed", f"{user_id}:{body.role}"
    )
    return {"role": body.role}


@app.delete("/t/{tenant_slug}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(user_id: UUID, context: MemberManager) -> None:
    db, principal = context
    target = await queries.membership(db, principal.tenant_id, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    if target["rank"] > principal.rank:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "That is above your own role")
    if target["role"] == "owner" and await queries.owner_count(db) == 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "A tenant must keep at least one owner")
    await queries.remove_member(db, user_id)
    await queries.audit(db, principal.tenant_id, principal.user_id, "member.removed", str(user_id))


@app.get("/t/{tenant_slug}/audit")
async def audit_log(context: AuditReader) -> list[dict]:
    return await queries.audit_entries(context[0])


@app.post("/t/{tenant_slug}/suspend")
async def suspend_tenant(context: OrgManager) -> dict:
    db, principal = context
    await queries.set_tenant_status(db, principal.tenant_id, "suspended")
    await queries.audit(db, principal.tenant_id, principal.user_id, "tenant.suspended")
    return {"status": "suspended"}


@app.get("/t/{tenant_slug}/export")
async def export_tenant(context: OrgManager) -> dict:
    db, principal = context
    await queries.audit(db, principal.tenant_id, principal.user_id, "tenant.exported")
    return {
        "projects": await queries.list_projects(db),
        "documents": await queries.list_documents(db, clearance=1),
        "members": await queries.list_members(db),
    }


@app.delete("/t/{tenant_slug}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(context: OrgManager) -> None:
    db, principal = context
    await queries.delete_tenant(db, principal.tenant_id)


@app.get("/support/t/{tenant_slug}/documents")
async def support_view(tenant_slug: str, identity: IdentityDep) -> list[dict]:
    """Read-only support access through a separate database role, with a required live grant."""
    async with tenant_transaction() as db:
        user_id = await queries.find_or_create_user(db, identity)
        tenant = await queries.tenant_by_slug(db, tenant_slug)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")

    async with tenant_transaction(user_id=user_id, database=support_engine) as db:
        documents = await queries.list_documents(db, clearance=1)
        visible = [d for d in documents if d["id"]]
        if not visible:
            return []
        await queries.audit(db, tenant["id"], user_id, "support.viewed", tenant_slug)
    return visible


async def run_tenant_job(tenant_id: UUID, job) -> None:
    """Background jobs have no request, so each must state its tenant explicitly."""
    async with tenant_transaction(tenant_id) as db:
        await job(db)
