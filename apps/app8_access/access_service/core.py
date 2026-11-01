"""Shared pieces of the Access Service: token checks, versions, and loading facts."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncConnection

from apps.app2_oidc.oidc import OidcProvider, TokenError
from apps.app8_access.access_service import db as database
from apps.app8_access.access_service.db import one, run
from apps.app8_access.access_service.decision import Facts, Grant
from apps.app8_access.access_service.settings import settings

bearer = HTTPBearer(auto_error=False)
default_provider = OidcProvider(settings.issuer)
default_redis = Redis.from_url(settings.redis_url, decode_responses=True)


def get_provider() -> OidcProvider:
    return default_provider


def get_redis() -> Redis:
    return default_redis


RedisDep = Annotated[Redis, Depends(get_redis)]
ProviderDep = Annotated[OidcProvider, Depends(get_provider)]
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


async def access_token_claims(provider: ProviderDep, credentials: Credentials) -> dict:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        return await provider.validate_access_token(credentials.credentials, settings.audience)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc


ClaimsDep = Annotated[dict, Depends(access_token_claims)]


async def bump_user(redis: Redis, subject: str) -> None:
    """Apps put this number in their cache keys, so a change invalidates cached decisions.

    If Redis is down, the change still applies once the short cache lifetime runs out.
    """
    try:
        await redis.incr(f"ver:user:{subject}")
    except RedisError:
        return


async def bump_everyone(redis: Redis) -> None:
    try:
        await redis.incr("ver:all")
    except RedisError:
        return


async def upsert_user(
    db: AsyncConnection, tenant_id: UUID, issuer: str, subject: str, email: str, name: str
) -> dict:
    """Someone seen for the first time is created with no access at all."""
    known = await one(
        db,
        """
        SELECT u.id, u.subject, u.email, u.name, u.status
        FROM users u JOIN tenant_users m ON m.user_id = u.id
        WHERE u.issuer = :i AND u.subject = :s
          AND u.last_seen_at > now() - interval '5 minutes'
          AND (:e = '' OR u.email = :e)
        """,
        i=issuer,
        s=subject,
        e=email,
    )
    # Most checks are for someone seen moments ago, so most checks need no write at all.
    if known:
        return known

    user = await one(
        db,
        """
        INSERT INTO users (issuer, subject, email, name, last_seen_at)
        VALUES (:i, :s, :e, :n, now())
        ON CONFLICT (issuer, subject) DO UPDATE
            SET email = COALESCE(NULLIF(EXCLUDED.email, ''), users.email),
                name = COALESCE(NULLIF(EXCLUDED.name, ''), users.name),
                last_seen_at = now()
        RETURNING id, subject, email, name, status
        """,
        i=issuer,
        s=subject,
        e=email,
        n=name,
    )
    # The users table is shared, so this is what ties a person to this tenant.
    await run(
        db,
        "INSERT INTO tenant_users VALUES (:t, :u) ON CONFLICT DO NOTHING",
        t=tenant_id,
        u=user["id"],
    )
    return user


FACTS_SQL = """
SELECT
    now() AS now,
    (SELECT COALESCE(json_agg(row_to_json(d)), '[]') FROM (
        SELECT t.key, t.rank, g.status, g.starts_at, g.expires_at
        FROM user_app_access g JOIN tiers t ON t.id = g.tier_id
        WHERE g.user_id = :u AND g.application_id = :a AND g.status <> 'revoked'
    ) d) AS direct,
    (SELECT COALESCE(json_agg(row_to_json(g)), '[]') FROM (
        SELECT t.key, t.rank
        FROM group_members m
        JOIN group_app_access a ON a.group_id = m.group_id
        JOIN tiers t ON t.id = a.tier_id
        WHERE m.user_id = :u AND a.application_id = :a
    ) g) AS through_groups,
    (SELECT row_to_json(l) FROM (
        SELECT t.rank, l.expires_at <= now() AS expired
        FROM tenant_app_licenses l JOIN tiers t ON t.id = l.tier_id
        WHERE l.application_id = :a
    ) l) AS license,
    (SELECT COALESCE(json_agg(row_to_json(t)), '[]') FROM (
        SELECT key, rank FROM tiers WHERE application_id = :a
    ) t) AS tiers,
    (SELECT COALESCE(json_agg(row_to_json(f)), '[]') FROM (
        SELECT t.key AS tier, f.key AS feature, tf.limit_value
        FROM tier_features tf
        JOIN tiers t ON t.id = tf.tier_id
        JOIN features f ON f.id = tf.feature_id
        WHERE t.application_id = :a
    ) f) AS features
"""


def parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


async def load_facts(db: AsyncConnection, user: dict, tenant: dict, application: dict) -> Facts:
    """One statement, so a decision costs one trip to the database. The clock is the database's."""
    row = await one(db, FACTS_SQL, u=user["id"], a=application["id"])

    tier_features: dict[str, dict[str, int | None]] = {}
    for item in row["features"]:
        tier_features.setdefault(item["tier"], {})[item["feature"]] = item["limit_value"]

    license_rank = None
    if row["license"]:
        license_rank = 0 if row["license"]["expired"] else row["license"]["rank"]

    grants = [
        Grant(
            g["key"],
            g["rank"],
            g["status"],
            parse_time(g["starts_at"]),
            parse_time(g["expires_at"]),
        )
        for g in row["direct"]
    ] + [Grant(g["key"], g["rank"], direct=False) for g in row["through_groups"]]

    return Facts(
        now=row["now"],
        user_status=user["status"],
        tenant_status=tenant["status"],
        app_status=application["status"],
        grants=tuple(grants),
        license_rank=license_rank,
        tiers={item["rank"]: item["key"] for item in row["tiers"]},
        tier_features=tier_features,
    )


async def tenant_by_slug(slug: str) -> dict | None:
    async with database.tenant_tx() as db:
        return await one(db, "SELECT * FROM tenants WHERE slug = :s", s=slug)


async def application_by_id(db: AsyncConnection, application_id: UUID) -> dict | None:
    return await one(db, "SELECT * FROM applications WHERE id = :i", i=application_id)


async def touch_review(db: AsyncConnection, grant_id: UUID) -> None:
    await run(db, "UPDATE user_app_access SET reviewed_at = now() WHERE id = :i", i=grant_id)
