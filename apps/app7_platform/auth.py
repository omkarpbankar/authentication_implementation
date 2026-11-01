"""From a request to a Principal: who is this, in which tenant, and what may they do."""

import time
import uuid
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

import jwt
import structlog
from fastapi import Depends, HTTPException, Path, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncConnection

from apps.app1_jwt.keys import KeyRing
from apps.app2_oidc.oidc import OidcProvider, TokenError
from apps.app7_platform import queries
from apps.app7_platform.database import tenant_transaction
from apps.app7_platform.identity import KeycloakAdapter, TokenVerifier
from apps.app7_platform.settings import settings
from apps.shared.rate_limit import RateLimiter

bearer = HTTPBearer(auto_error=False)
key_ring = KeyRing.load_or_create(settings.keys_dir)
default_verifier = TokenVerifier(
    [KeycloakAdapter(OidcProvider(settings.keycloak_issuer), settings.audience)]
)


def get_key_ring() -> KeyRing:
    return key_ring


limiter_redis = Redis.from_url(settings.redis_url, decode_responses=True)


def get_limiter() -> RateLimiter:
    return RateLimiter(limiter_redis)


def get_verifier() -> TokenVerifier:
    return default_verifier


Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]
KeyRingDep = Annotated[KeyRing, Depends(get_key_ring)]


def unauthorized() -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def create_tenant_token(ring: KeyRing, user_id: UUID, tenant_id: UUID) -> str:
    """A short-lived token valid for exactly one tenant, which makes switching explicit."""
    now = int(time.time())
    return jwt.encode(
        {
            "iss": settings.issuer,
            "aud": settings.audience,
            "sub": str(user_id),
            "tid": str(tenant_id),
            "iat": now,
            "exp": now + settings.access_ttl_seconds,
            "jti": str(uuid.uuid4()),
        },
        ring.active_key,
        algorithm="RS256",
        headers={"kid": ring.active_kid},
    )


def read_tenant_token(token: str, ring: KeyRing) -> dict:
    try:
        key = ring.public_key(jwt.get_unverified_header(token).get("kid", ""))
        if key is None:
            raise TokenError("Unknown key")
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.audience,
            issuer=settings.issuer,
            options={"require": ["exp", "iss", "aud", "sub", "tid"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    tenant_slug: str
    role: str
    rank: int
    clearance: int
    permissions: frozenset[str]

    def can(self, permission: str) -> bool:
        return permission in self.permissions


async def tenant_db(
    credentials: Credentials,
    ring: KeyRingDep,
    tenant_slug: Annotated[str, Path()],
):
    """Authenticates the request, and opens a transaction limited to that tenant.

    Everything is checked again on each request, so removing a member or suspending a tenant
    works immediately, even while a token is still valid.
    """
    if credentials is None:
        raise unauthorized()
    try:
        claims = read_tenant_token(credentials.credentials, ring)
    except TokenError as exc:
        raise unauthorized() from exc

    tenant_id, user_id = UUID(claims["tid"]), UUID(claims["sub"])
    # Every log line for this request now names its tenant, which helps in an investigation.
    structlog.contextvars.bind_contextvars(tenant_id=str(tenant_id))
    async with tenant_transaction(tenant_id, user_id) as db:
        tenant = await queries.tenant_by_id(db, tenant_id)
        # The URL must agree with the token, so a token for one tenant cannot open another.
        if tenant is None or tenant["slug"] != tenant_slug:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Token is not valid for this tenant")
        if tenant["status"] != "active":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This organization is suspended")
        if not await get_limiter().allow(
            f"tenant:{tenant_id}:requests", settings.tenant_requests_per_minute, 60
        ):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")

        member = await queries.membership(db, tenant_id, user_id)
        if member is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You are not a member of this tenant")

        yield (
            db,
            Principal(
                user_id=user_id,
                tenant_id=tenant_id,
                tenant_slug=tenant_slug,
                role=member["role"],
                rank=member["rank"],
                clearance=member["clearance"],
                permissions=frozenset(member["permissions"]),
            ),
        )


TenantContext = tuple[AsyncConnection, Principal]
TenantDep = Annotated[TenantContext, Depends(tenant_db, scope="function")]


def require_permission(permission: str):
    """Code checks permissions, never role names, so roles can change without a code change."""

    def check(context: TenantDep) -> TenantContext:
        if not context[1].can(permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission}")
        return context

    return check
