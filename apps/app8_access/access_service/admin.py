"""The admin API. Every rule lives here, so skipping the admin panel gains nothing."""

import csv
import io
import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError

from apps.app8_access.access_service import db as database
from apps.app8_access.access_service.core import (
    ClaimsDep,
    RedisDep,
    bump_everyone,
    bump_user,
    tenant_by_slug,
    touch_review,
    upsert_user,
)
from apps.app8_access.access_service.db import audit, many, one, run
from apps.app8_access.access_service.settings import settings

router = APIRouter(prefix="/admin/v1", tags=["Admin"])

INACTIVE_AFTER_DAYS = 60
EVERYTHING = {"view", "grant", "suspend", "manage_apps", "manage_admins", "audit"}
ROLE_ACTIONS = {
    "super_admin": EVERYTHING,
    "app_admin": {"view", "grant", "suspend", "audit"},
    "helpdesk": {"view", "suspend"},
    "auditor": {"view", "audit"},
}
LIVE_GRANTS = "status <> 'revoked' AND (expires_at IS NULL OR expires_at > now())"


@dataclass(frozen=True)
class Admin:
    user_id: UUID
    tenant_id: UUID
    role: str
    application_id: UUID | None
    subject: str
    authenticated_at: int

    def can(self, action: str, application_id: UUID | None = None) -> bool:
        if action not in ROLE_ACTIONS[self.role]:
            return False
        # An App Admin's power stops at the edge of their own application.
        if self.role == "app_admin" and application_id is not None:
            return application_id == self.application_id
        return True


async def current_admin(claims: ClaimsDep) -> Admin:
    # The panel checks this too, but the rule must hold for direct API calls as well.
    if "otp" not in (claims.get("amr") or []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Multi-factor sign-in is required")

    organizations = claims.get("organization") or []
    tenant = await tenant_by_slug(organizations[0]) if organizations else None
    if tenant is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not an admin")

    async with database.tenant_tx(tenant["id"]) as db:
        user = await upsert_user(
            db,
            tenant["id"],
            claims["iss"],
            claims["sub"],
            claims.get("email", ""),
            claims.get("name", ""),
        )
        role = await one(
            db,
            "SELECT role, application_id FROM admin_roles WHERE user_id = :u",
            u=user["id"],
        )
    if role is None or user["status"] != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not an admin")
    return Admin(
        user["id"],
        tenant["id"],
        role["role"],
        role["application_id"],
        claims["sub"],
        int(claims.get("auth_time", 0)),
    )


AdminDep = Annotated[Admin, Depends(current_admin)]


def require(admin: Admin, action: str, application_id: UUID | None = None) -> None:
    if not admin.can(action, application_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your admin role does not allow this")


def require_recent_sign_in(admin: Admin) -> None:
    if time.time() - admin.authenticated_at > settings.reauth_seconds:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "REAUTH_REQUIRED")


def forbid_self(admin: Admin, user_id: UUID) -> None:
    # Separation of duties: nobody approves their own access.
    if admin.user_id == user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot change your own access")


class GrantChange(BaseModel):
    tier: str
    reason: str = Field(min_length=3, max_length=500)
    starts_at: datetime | None = None
    expires_at: datetime | None = None
    expected_version: int | None = None


class ReasonOnly(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class ApplicationStatus(BaseModel):
    status: str = Field(pattern="^(active|maintenance|retired)$")
    reason: str = Field(min_length=3, max_length=500)


class TierFeature(BaseModel):
    feature: str
    limit_value: int | None = None
    reason: str = Field(min_length=3, max_length=500)


class NewTier(BaseModel):
    key: str = Field(pattern="^[a-z]{2,20}$")
    rank: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)


class NewGroup(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class GroupGrant(BaseModel):
    application_id: UUID
    tier: str
    reason: str = Field(min_length=3, max_length=500)


class AdminAssignment(BaseModel):
    role: str = Field(pattern="^(super_admin|app_admin|helpdesk|auditor)$")
    application_id: UUID | None = None
    reason: str = Field(min_length=3, max_length=500)


class BulkUpload(BaseModel):
    csv: str = Field(max_length=200_000)
    reason: str = Field(default="Bulk change", min_length=3, max_length=500)


class Review(BaseModel):
    tier: str = ""
    reason: str = Field(default="Approved", min_length=3, max_length=500)


def csv_safe(value) -> str:
    """Spreadsheets run cells starting with these characters, which is an attack on admins."""
    text = "" if value is None else str(value)
    return f"'{text}" if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


async def user_row(db, user_id: UUID) -> dict:
    # Row-level security on tenant_users means a user in another tenant is simply not found.
    user = await one(
        db,
        """
        SELECT u.* FROM users u JOIN tenant_users m ON m.user_id = u.id WHERE u.id = :u
        """,
        u=user_id,
    )
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


async def tier_row(db, application_id: UUID, key: str) -> dict:
    tier = await one(
        db, "SELECT * FROM tiers WHERE application_id = :a AND key = :k", a=application_id, k=key
    )
    if tier is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown tier")
    return tier


async def check_seats(db, tenant_id: UUID, application_id: UUID, user_id: UUID) -> None:
    # FOR UPDATE makes two admins take turns, so they cannot both use the last seat.
    license_row = await one(
        db,
        """
        SELECT seat_limit FROM tenant_app_licenses
        WHERE application_id = :a AND tenant_id = :t FOR UPDATE
        """,
        a=application_id,
        t=tenant_id,
    )
    if license_row is None or license_row["seat_limit"] is None:
        return
    used = await one(
        db,
        f"""
        SELECT count(*) AS total FROM user_app_access
        WHERE application_id = :a AND user_id <> :u AND {LIVE_GRANTS}
        """,
        a=application_id,
        u=user_id,
    )
    if used["total"] >= license_row["seat_limit"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "No seats left on this license")


async def set_grant(
    db,
    admin: Admin,
    user_id: UUID,
    application_id: UUID,
    change: GrantChange,
    source: str = "admin",
) -> dict:
    tier = await tier_row(db, application_id, change.tier)
    await check_seats(db, admin.tenant_id, application_id, user_id)

    existing = await one(
        db,
        """
        SELECT g.*, t.key AS tier FROM user_app_access g JOIN tiers t ON t.id = g.tier_id
        WHERE g.user_id = :u AND g.application_id = :a AND g.status <> 'revoked' FOR UPDATE OF g
        """,
        u=user_id,
        a=application_id,
    )
    if (
        change.expected_version is not None
        and existing
        and existing["version"] != change.expected_version
    ):
        # Another admin changed this after the page was opened. Show them, and do not overwrite.
        raise HTTPException(status.HTTP_409_CONFLICT, "This grant has changed. Reload and retry.")

    if existing:
        await run(
            db,
            """
            UPDATE user_app_access
            SET tier_id = :t, status = 'active', starts_at = :s, expires_at = :e, reason = :r,
                granted_by = :by, source = :src, version = version + 1
            WHERE id = :i
            """,
            t=tier["id"],
            s=change.starts_at,
            e=change.expires_at,
            r=change.reason,
            by=admin.user_id,
            src=source,
            i=existing["id"],
        )
    else:
        await run(
            db,
            """
            INSERT INTO user_app_access
                (tenant_id, user_id, application_id, tier_id, starts_at, expires_at, source,
                 granted_by, reason)
            VALUES (:tn, :u, :a, :t, :s, :e, :src, :by, :r)
            """,
            tn=admin.tenant_id,
            u=user_id,
            a=application_id,
            t=tier["id"],
            s=change.starts_at,
            e=change.expires_at,
            src=source,
            by=admin.user_id,
            r=change.reason,
        )
    await audit(
        db,
        admin.tenant_id,
        admin.user_id,
        "grant.set",
        f"{user_id}:{application_id}",
        before=json.dumps({"tier": existing["tier"]}) if existing else None,
        after=json.dumps({"tier": change.tier}),
        reason=change.reason,
    )
    return {"tier": change.tier}


async def first_use(redis, key: str | None) -> bool:
    """Double-clicks and retries repeat this key, so the action runs only once."""
    if not key:
        return True
    try:
        return bool(await redis.set(f"idem:{key}", "1", nx=True, ex=86400))
    except RedisError:
        return True


@router.get("/whoami")
async def whoami(admin: AdminDep) -> dict:
    return {
        "role": admin.role,
        "application_id": admin.application_id,
        "actions": sorted(ROLE_ACTIONS[admin.role]),
        "user_id": admin.user_id,
    }


@router.get("/dashboard")
async def dashboard(admin: AdminDep) -> dict:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        counts = await one(
            db,
            f"""
            SELECT
              (SELECT count(*) FROM user_app_access WHERE {LIVE_GRANTS}) AS live_grants,
              (SELECT count(*) FROM access_requests WHERE status = 'open') AS open_requests,
              (SELECT count(*) FROM user_app_access WHERE status <> 'revoked'
                 AND expires_at BETWEEN now() AND now() + interval '7 days') AS expiring_soon
            """,
        )
        recent = await many(
            db,
            """
            SELECT action, target, reason, at FROM access_audit_log
            WHERE action <> 'access.denied' ORDER BY id DESC LIMIT 10
            """,
        )
    return {**counts, "recent": recent}


@router.get("/users")
async def list_users(
    admin: AdminDep,
    q: str = "",
    app_key: str = "",
    tier: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        return await many(
            db,
            """
            SELECT DISTINCT u.id, u.email, u.name, u.status, u.last_seen_at
            FROM users u
            JOIN tenant_users m ON m.user_id = u.id
            LEFT JOIN user_app_access g ON g.user_id = u.id AND g.status <> 'revoked'
            LEFT JOIN applications a ON a.id = g.application_id
            LEFT JOIN tiers t ON t.id = g.tier_id
            WHERE (u.email ILIKE :q OR u.name ILIKE :q)
              AND (:app = '' OR a.app_key = :app)
              AND (:tier = '' OR t.key = :tier)
            ORDER BY u.email LIMIT :limit OFFSET :offset
            """,
            q=f"%{q}%",
            app=app_key,
            tier=tier,
            limit=min(limit, 200),
            offset=max(offset, 0),
        )


@router.get("/users/{user_id}")
async def user_detail(user_id: UUID, admin: AdminDep) -> dict:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        applications = await many(
            db,
            """
            SELECT a.id, a.app_key, a.name, g.id AS grant_id, t.key AS tier, g.status,
                   g.starts_at, g.expires_at, g.version, g.source, g.reason
            FROM applications a
            LEFT JOIN user_app_access g
                ON g.application_id = a.id AND g.user_id = :u AND g.status <> 'revoked'
            LEFT JOIN tiers t ON t.id = g.tier_id
            ORDER BY a.app_key
            """,
            u=user_id,
        )
        history = await many(
            db,
            """
            SELECT action, target, reason, at FROM access_audit_log
            WHERE target LIKE :t OR actor_id = :u ORDER BY id DESC LIMIT 25
            """,
            t=f"{user_id}%",
            u=user_id,
        )
    visible = [a for a in applications if admin.can("view", a["id"])]
    return {"user": user, "applications": visible, "history": history}


@router.put("/users/{user_id}/grants/{application_id}")
async def put_grant(
    user_id: UUID,
    application_id: UUID,
    change: GrantChange,
    admin: AdminDep,
    redis: RedisDep,
    idempotency_key: Annotated[str | None, Header()] = None,
) -> dict:
    require(admin, "grant", application_id)
    forbid_self(admin, user_id)
    if not await first_use(redis, idempotency_key):
        return {"tier": change.tier, "duplicate": True}

    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        result = await set_grant(db, admin, user_id, application_id, change)
    await bump_user(redis, user["subject"])
    return result


async def change_status(
    admin: Admin,
    redis,
    user_id: UUID,
    application_id: UUID,
    new_status: str,
    reason: str,
) -> dict:
    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        grant = await one(
            db,
            """
            SELECT id FROM user_app_access
            WHERE user_id = :u AND application_id = :a AND status <> 'revoked' FOR UPDATE
            """,
            u=user_id,
            a=application_id,
        )
        if grant is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No grant to change")
        await run(
            db,
            "UPDATE user_app_access SET status = :s, version = version + 1 WHERE id = :i",
            s=new_status,
            i=grant["id"],
        )
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            f"grant.{new_status}",
            f"{user_id}:{application_id}",
            reason=reason,
        )
    await bump_user(redis, user["subject"])
    return {"status": new_status}


@router.post("/users/{user_id}/grants/{application_id}/suspend")
async def suspend_grant(
    user_id: UUID, application_id: UUID, body: ReasonOnly, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "suspend", application_id)
    forbid_self(admin, user_id)
    return await change_status(admin, redis, user_id, application_id, "suspended", body.reason)


@router.post("/users/{user_id}/grants/{application_id}/resume")
async def resume_grant(
    user_id: UUID, application_id: UUID, body: ReasonOnly, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "grant", application_id)
    forbid_self(admin, user_id)
    return await change_status(admin, redis, user_id, application_id, "active", body.reason)


@router.post("/users/{user_id}/grants/{application_id}/revoke")
async def revoke_grant(
    user_id: UUID, application_id: UUID, body: ReasonOnly, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "grant", application_id)
    forbid_self(admin, user_id)
    return await change_status(admin, redis, user_id, application_id, "revoked", body.reason)


@router.post("/users/{user_id}/disable")
async def disable_user(user_id: UUID, body: ReasonOnly, admin: AdminDep, redis: RedisDep) -> dict:
    """The leaver path. A company directory calls this through SCIM, or an admin does."""
    require(admin, "manage_admins")
    forbid_self(admin, user_id)
    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        await run(db, "UPDATE users SET status = 'disabled' WHERE id = :u", u=user_id)
        await audit(
            db, admin.tenant_id, admin.user_id, "user.disabled", str(user_id), reason=body.reason
        )
    await bump_user(redis, user["subject"])
    return {"status": "disabled"}


@router.post("/users/{user_id}/erase")
async def erase_user(user_id: UUID, body: ReasonOnly, admin: AdminDep, redis: RedisDep) -> dict:
    """Removes personal data. Audit rows keep the anonymous ID, so history stays intact."""
    require(admin, "manage_admins")
    forbid_self(admin, user_id)
    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        await run(
            db,
            """
            UPDATE users SET email = '', name = '', status = 'disabled', subject = :anon
            WHERE id = :u
            """,
            anon=f"erased:{user_id}",
            u=user_id,
        )
        await run(
            db,
            "UPDATE user_app_access SET status = 'revoked' WHERE user_id = :u",
            u=user_id,
        )
        await audit(
            db, admin.tenant_id, admin.user_id, "user.erased", str(user_id), reason=body.reason
        )
    await bump_user(redis, user["subject"])
    return {"status": "erased"}


@router.get("/matrix")
async def matrix(admin: AdminDep) -> dict:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        applications = await many(
            db, "SELECT id, app_key, name, status FROM applications ORDER BY app_key"
        )
        users = await many(
            db,
            """
            SELECT DISTINCT u.id, u.email, u.status
            FROM users u JOIN tenant_users m ON m.user_id = u.id
            WHERE u.email <> '' ORDER BY u.email LIMIT 200
            """,
        )
        grants = await many(
            db,
            """
            SELECT g.user_id, g.application_id, t.key AS tier, g.status
            FROM user_app_access g JOIN tiers t ON t.id = g.tier_id
            WHERE g.status <> 'revoked'
            """,
        )
    lookup = {(str(g["user_id"]), str(g["application_id"])): g for g in grants}
    return {
        "applications": [a for a in applications if admin.can("view", a["id"])],
        "users": [
            {
                **user,
                "grants": {
                    a["app_key"]: lookup.get((str(user["id"]), str(a["id"]))) for a in applications
                },
            }
            for user in users
        ],
    }


@router.get("/applications")
async def list_applications(admin: AdminDep) -> list[dict]:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        applications = await many(db, "SELECT * FROM applications ORDER BY app_key")
        for application in applications:
            application["clients"] = await many(
                db,
                "SELECT client_id, environment FROM application_clients WHERE application_id = :a",
                a=application["id"],
            )
            application["tiers"] = await many(
                db,
                """
                SELECT t.id, t.key, t.rank,
                       (SELECT count(*) FROM user_app_access g
                        WHERE g.tier_id = t.id AND g.status <> 'revoked') AS holders
                FROM tiers t WHERE t.application_id = :a ORDER BY t.rank
                """,
                a=application["id"],
            )
    return applications


@router.put("/applications/{application_id}/status")
async def set_application_status(
    application_id: UUID, body: ApplicationStatus, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "manage_apps")
    async with database.tenant_tx(admin.tenant_id) as db:
        await run(
            db, "UPDATE applications SET status = :s WHERE id = :a", s=body.status, a=application_id
        )
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            "application.status",
            str(application_id),
            reason=body.reason,
            after=json.dumps({"status": body.status}),
        )
    await bump_everyone(redis)
    return {"status": body.status}


@router.post("/applications/{application_id}/tiers", status_code=status.HTTP_201_CREATED)
async def add_tier(application_id: UUID, body: NewTier, admin: AdminDep, redis: RedisDep) -> dict:
    require(admin, "manage_apps")
    try:
        async with database.tenant_tx(admin.tenant_id) as db:
            await run(
                db,
                "INSERT INTO tiers (application_id, key, rank) VALUES (:a, :k, :r)",
                a=application_id,
                k=body.key,
                r=body.rank,
            )
            await audit(
                db,
                admin.tenant_id,
                admin.user_id,
                "tier.created",
                body.key,
                reason=body.reason,
            )
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "That tier or rank already exists") from exc
    await bump_everyone(redis)
    return {"key": body.key}


@router.delete("/applications/{application_id}/tiers/{key}")
async def delete_tier(
    application_id: UUID, key: str, body: ReasonOnly, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "manage_apps")
    try:
        async with database.tenant_tx(admin.tenant_id) as db:
            tier = await tier_row(db, application_id, key)
            await run(db, "DELETE FROM tiers WHERE id = :t", t=tier["id"])
            await audit(db, admin.tenant_id, admin.user_id, "tier.deleted", key, reason=body.reason)
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Move everyone off this tier before deleting it"
        ) from exc
    await bump_everyone(redis)
    return {"deleted": key}


@router.put("/applications/{application_id}/tiers/{key}/features")
async def set_tier_feature(
    application_id: UUID, key: str, body: TierFeature, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "manage_apps")
    async with database.tenant_tx(admin.tenant_id) as db:
        tier = await tier_row(db, application_id, key)
        await run(
            db,
            """
            INSERT INTO tier_features (tier_id, feature_id, limit_value)
            SELECT :t, f.id, :l FROM features f WHERE f.key = :f AND f.application_id = :a
            ON CONFLICT (tier_id, feature_id) DO UPDATE SET limit_value = EXCLUDED.limit_value
            """,
            t=tier["id"],
            l=body.limit_value,
            f=body.feature,
            a=application_id,
        )
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            "tier.feature_set",
            f"{key}:{body.feature}",
            reason=body.reason,
        )
    await bump_everyone(redis)
    return {"feature": body.feature}


@router.get("/groups")
async def list_groups(admin: AdminDep) -> list[dict]:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        groups = await many(db, "SELECT id, name FROM groups ORDER BY name")
        for group in groups:
            group["members"] = await many(
                db,
                """
                SELECT u.id, u.email FROM group_members m JOIN users u ON u.id = m.user_id
                WHERE m.group_id = :g ORDER BY u.email
                """,
                g=group["id"],
            )
            group["grants"] = await many(
                db,
                """
                SELECT a.app_key, t.key AS tier, a.id AS application_id
                FROM group_app_access g
                JOIN applications a ON a.id = g.application_id
                JOIN tiers t ON t.id = g.tier_id
                WHERE g.group_id = :g
                """,
                g=group["id"],
            )
    return groups


@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(body: NewGroup, admin: AdminDep) -> dict:
    require(admin, "grant")
    try:
        async with database.tenant_tx(admin.tenant_id) as db:
            group = await one(
                db,
                "INSERT INTO groups (tenant_id, name) VALUES (:t, :n) RETURNING id, name",
                t=admin.tenant_id,
                n=body.name,
            )
            await audit(db, admin.tenant_id, admin.user_id, "group.created", body.name)
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "That group already exists") from exc
    return group


@router.put("/groups/{group_id}/members/{user_id}")
async def add_group_member(group_id: UUID, user_id: UUID, admin: AdminDep, redis: RedisDep) -> dict:
    require(admin, "grant")
    forbid_self(admin, user_id)
    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        await run(
            db,
            "INSERT INTO group_members VALUES (:t, :g, :u) ON CONFLICT DO NOTHING",
            t=admin.tenant_id,
            g=group_id,
            u=user_id,
        )
        await audit(
            db, admin.tenant_id, admin.user_id, "group.member_added", f"{group_id}:{user_id}"
        )
    await bump_user(redis, user["subject"])
    return {"added": True}


@router.delete("/groups/{group_id}/members/{user_id}")
async def remove_group_member(
    group_id: UUID, user_id: UUID, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "grant")
    async with database.tenant_tx(admin.tenant_id) as db:
        user = await user_row(db, user_id)
        await run(
            db,
            "DELETE FROM group_members WHERE group_id = :g AND user_id = :u",
            g=group_id,
            u=user_id,
        )
        await audit(
            db, admin.tenant_id, admin.user_id, "group.member_removed", f"{group_id}:{user_id}"
        )
    await bump_user(redis, user["subject"])
    return {"removed": True}


@router.put("/groups/{group_id}/grant")
async def set_group_grant(
    group_id: UUID, body: GroupGrant, admin: AdminDep, redis: RedisDep
) -> dict:
    require(admin, "grant", body.application_id)
    async with database.tenant_tx(admin.tenant_id) as db:
        tier = await tier_row(db, body.application_id, body.tier)
        await run(
            db,
            """
            INSERT INTO group_app_access VALUES (:t, :g, :a, :tier)
            ON CONFLICT (group_id, application_id) DO UPDATE SET tier_id = EXCLUDED.tier_id
            """,
            t=admin.tenant_id,
            g=group_id,
            a=body.application_id,
            tier=tier["id"],
        )
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            "group.grant_set",
            str(group_id),
            reason=body.reason,
        )
    await bump_everyone(redis)
    return {"tier": body.tier}


@router.get("/requests")
async def list_requests(admin: AdminDep) -> list[dict]:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        rows = await many(
            db,
            """
            SELECT r.id, r.requested_tier, r.note, r.created_at, r.application_id,
                   u.email, u.id AS user_id, a.name AS application
            FROM access_requests r
            JOIN users u ON u.id = r.user_id
            JOIN applications a ON a.id = r.application_id
            WHERE r.status = 'open' ORDER BY r.created_at
            """,
        )
    return [row for row in rows if admin.can("view", row["application_id"])]


async def open_request(db, request_id: UUID) -> dict:
    row = await one(
        db,
        """
        SELECT r.*, u.status AS user_status, u.subject
        FROM access_requests r JOIN users u ON u.id = r.user_id
        WHERE r.id = :i AND r.status = 'open' FOR UPDATE OF r
        """,
        i=request_id,
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Request not found or already handled")
    return row


@router.post("/requests/{request_id}/approve")
async def approve_request(request_id: UUID, body: Review, admin: AdminDep, redis: RedisDep) -> dict:
    async with database.tenant_tx(admin.tenant_id) as db:
        request = await open_request(db, request_id)
        require(admin, "grant", request["application_id"])
        forbid_self(admin, request["user_id"])
        if request["user_status"] != "active":
            raise HTTPException(status.HTTP_409_CONFLICT, "That user is disabled")
        tier = body.tier or request["requested_tier"]
        await set_grant(
            db,
            admin,
            request["user_id"],
            request["application_id"],
            GrantChange(tier=tier, reason=body.reason),
            source="request",
        )
        await run(
            db,
            "UPDATE access_requests SET status = 'approved', reviewed_by = :a WHERE id = :i",
            a=admin.user_id,
            i=request_id,
        )
    await bump_user(redis, request["subject"])
    return {"tier": tier}


@router.post("/requests/{request_id}/reject")
async def reject_request(request_id: UUID, body: ReasonOnly, admin: AdminDep) -> dict:
    async with database.tenant_tx(admin.tenant_id) as db:
        request = await open_request(db, request_id)
        require(admin, "grant", request["application_id"])
        await run(
            db,
            "UPDATE access_requests SET status = 'rejected', reviewed_by = :a WHERE id = :i",
            a=admin.user_id,
            i=request_id,
        )
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            "request.rejected",
            str(request_id),
            reason=body.reason,
        )
    return {"status": "rejected"}


async def parse_bulk(db, text: str) -> list[dict]:
    """Check every row, and describe what it would do, without changing anything."""
    applications = {
        row["app_key"]: row["id"] for row in await many(db, "SELECT id, app_key FROM applications")
    }
    rows = []
    for number, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
        email = (row.get("email") or "").strip().lower()
        app_key = (row.get("app_key") or "").strip()
        tier = (row.get("tier") or "").strip()
        entry = {"line": number, "email": email, "app_key": app_key, "tier": tier, "error": ""}
        user = await one(
            db,
            """
            SELECT u.id FROM users u JOIN tenant_users m ON m.user_id = u.id
            WHERE lower(u.email) = :e
            """,
            e=email,
        )
        application_id = applications.get(app_key)
        if user is None:
            entry["error"] = "Unknown user"
        elif application_id is None:
            entry["error"] = "Unknown application"
        elif not await one(
            db, "SELECT 1 AS ok FROM tiers WHERE application_id = :a AND key = :t",
            a=application_id, t=tier,
        ):  # fmt: skip
            entry["error"] = "Unknown tier"
        else:
            current = await one(
                db,
                """
                SELECT t.key FROM user_app_access g JOIN tiers t ON t.id = g.tier_id
                WHERE g.user_id = :u AND g.application_id = :a AND g.status <> 'revoked'
                """,
                u=user["id"],
                a=application_id,
            )
            entry["user_id"] = user["id"]
            entry["application_id"] = application_id
            if current is None:
                entry["change"] = "create"
            elif current["key"] == tier:
                entry["change"] = "unchanged"
            else:
                entry["change"] = f"{current['key']} to {tier}"
        rows.append(entry)
    return rows


@router.post("/bulk/preview")
async def bulk_preview(body: BulkUpload, admin: AdminDep) -> dict:
    require(admin, "grant")
    async with database.tenant_tx(admin.tenant_id) as db:
        rows = await parse_bulk(db, body.csv)
    return {"rows": rows, "errors": sum(1 for row in rows if row["error"])}


@router.post("/bulk/apply")
async def bulk_apply(body: BulkUpload, admin: AdminDep, redis: RedisDep) -> dict:
    require(admin, "grant")
    require_recent_sign_in(admin)
    # One transaction, so a problem in any row leaves everything exactly as it was.
    async with database.tenant_tx(admin.tenant_id) as db:
        rows = await parse_bulk(db, body.csv)
        if any(row["error"] for row in rows):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Fix the errors first")
        changed = []
        for row in rows:
            if row["change"] == "unchanged":
                continue
            require(admin, "grant", row["application_id"])
            forbid_self(admin, row["user_id"])
            await set_grant(
                db,
                admin,
                row["user_id"],
                row["application_id"],
                GrantChange(tier=row["tier"], reason=body.reason),
                source="bulk",
            )
            changed.append(row["user_id"])
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            "bulk.applied",
            f"{len(changed)} rows",
            reason=body.reason,
        )
    if changed:
        await bump_everyone(redis)
    return {"changed": len(changed), "unchanged": len(rows) - len(changed)}


@router.get("/reviews")
async def access_reviews(admin: AdminDep) -> list[dict]:
    require(admin, "view")
    async with database.tenant_tx(admin.tenant_id) as db:
        rows = await many(
            db,
            f"""
            SELECT g.id, g.application_id, u.id AS user_id, u.email, a.name AS application,
                   t.key AS tier, g.reviewed_at, u.last_seen_at,
                   (u.last_seen_at IS NULL
                    OR u.last_seen_at < now() - interval '{INACTIVE_AFTER_DAYS} days') AS inactive
            FROM user_app_access g
            JOIN users u ON u.id = g.user_id
            JOIN applications a ON a.id = g.application_id
            JOIN tiers t ON t.id = g.tier_id
            WHERE g.status = 'active'
            ORDER BY g.reviewed_at NULLS FIRST, u.email
            """,
        )
    return [row for row in rows if admin.can("view", row["application_id"])]


@router.post("/reviews/{grant_id}/confirm")
async def confirm_review(grant_id: UUID, admin: AdminDep) -> dict:
    require(admin, "grant")
    async with database.tenant_tx(admin.tenant_id) as db:
        await touch_review(db, grant_id)
        await audit(db, admin.tenant_id, admin.user_id, "review.confirmed", str(grant_id))
    return {"confirmed": True}


@router.get("/audit")
async def audit_log(admin: AdminDep, reference: str = "", limit: int = 100) -> list[dict]:
    require(admin, "audit")
    async with database.tenant_tx(admin.tenant_id) as db:
        return await many(
            db,
            """
            SELECT id, actor_id, action, target, before, after, reason, reference_id, at
            FROM access_audit_log
            WHERE (:r = '' OR reference_id = :r)
            ORDER BY id DESC LIMIT :limit
            """,
            r=reference,
            limit=min(limit, 500),
        )


@router.get("/audit.csv", response_class=PlainTextResponse)
async def audit_csv(admin: AdminDep) -> str:
    require(admin, "audit")
    rows = await audit_log(admin, limit=500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["at", "action", "target", "reason", "reference"])
    for row in rows:
        writer.writerow(
            [csv_safe(row[key]) for key in ("at", "action", "target", "reason", "reference_id")]
        )
    return output.getvalue()


@router.get("/admins")
async def list_admins(admin: AdminDep) -> list[dict]:
    require(admin, "manage_admins")
    async with database.tenant_tx(admin.tenant_id) as db:
        return await many(
            db,
            """
            SELECT r.user_id, u.email, r.role, r.application_id
            FROM admin_roles r JOIN users u ON u.id = r.user_id ORDER BY u.email
            """,
        )


async def super_admin_count(db) -> int:
    row = await one(db, "SELECT count(*) AS total FROM admin_roles WHERE role = 'super_admin'")
    return row["total"]


@router.put("/admins/{user_id}")
async def assign_admin(user_id: UUID, body: AdminAssignment, admin: AdminDep) -> dict:
    require(admin, "manage_admins")
    require_recent_sign_in(admin)
    forbid_self(admin, user_id)
    if body.role == "app_admin" and body.application_id is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Choose an application")
    async with database.tenant_tx(admin.tenant_id) as db:
        await user_row(db, user_id)
        await run(
            db,
            """
            INSERT INTO admin_roles (tenant_id, user_id, role, application_id)
            VALUES (:t, :u, :r, :a)
            ON CONFLICT (tenant_id, user_id)
            DO UPDATE SET role = EXCLUDED.role, application_id = EXCLUDED.application_id
            """,
            t=admin.tenant_id,
            u=user_id,
            r=body.role,
            a=body.application_id,
        )
        await audit(
            db,
            admin.tenant_id,
            admin.user_id,
            "admin.assigned",
            str(user_id),
            after=json.dumps({"role": body.role}),
            reason=body.reason,
        )
    return {"role": body.role}


@router.delete("/admins/{user_id}")
async def remove_admin(user_id: UUID, body: ReasonOnly, admin: AdminDep) -> dict:
    require(admin, "manage_admins")
    require_recent_sign_in(admin)
    async with database.tenant_tx(admin.tenant_id) as db:
        target = await one(db, "SELECT role FROM admin_roles WHERE user_id = :u", u=user_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not an admin")
        if target["role"] == "super_admin" and await super_admin_count(db) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "Keep at least one Super Admin")
        forbid_self(admin, user_id)
        await run(db, "DELETE FROM admin_roles WHERE user_id = :u", u=user_id)
        await audit(
            db, admin.tenant_id, admin.user_id, "admin.removed", str(user_id), reason=body.reason
        )
    return {"removed": True}
