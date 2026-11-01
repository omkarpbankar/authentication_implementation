"""Pieces shared by App 1's routes."""

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pydantic import BaseModel
from redis.asyncio import Redis

from apps.app1_jwt.keys import KeyRing
from apps.app1_jwt.settings import settings
from apps.app1_jwt.store import Store
from apps.app1_jwt.tokens import (
    AccessClaims,
    InvalidToken,
    create_access_token,
    new_refresh_token,
    verify_access_token,
)

password_hash = PasswordHash.recommended()
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
key_ring = KeyRing.load_or_create(settings.keys_dir)
bearer = HTTPBearer(auto_error=False)

# Verified for unknown emails too, so response time does not reveal which accounts exist.
DUMMY_HASH = password_hash.hash("not-a-real-account")


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int


def get_store() -> Store:
    return Store(redis_client, settings.refresh_ttl_seconds)


def get_key_ring() -> KeyRing:
    return key_ring


StoreDep = Annotated[Store, Depends(get_store)]
KeyRingDep = Annotated[KeyRing, Depends(get_key_ring)]


def unauthorized(detail: str = "Invalid or expired token") -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"}
    )


async def issue_pair(
    store: Store, ring: KeyRing, user_id: str, family_id: str | None = None
) -> TokenPair:
    family_id = family_id or str(uuid.uuid4())
    refresh_token = new_refresh_token()
    await store.save_refresh_token(refresh_token, user_id, family_id)
    access_token = create_access_token(
        ring,
        user_id,
        family_id,
        settings.issuer,
        settings.audience,
        settings.access_ttl_seconds,
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_ttl_seconds,
    )


async def current_claims(
    store: StoreDep,
    ring: KeyRingDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> AccessClaims:
    if credentials is None:
        raise unauthorized("Missing token")
    try:
        claims = verify_access_token(
            credentials.credentials, ring, settings.issuer, settings.audience
        )
    except InvalidToken as exc:
        # The reason stays out of the response, as it would only help an attacker.
        raise unauthorized() from exc
    if await store.is_access_token_denied(claims.jti):
        raise unauthorized()
    if await store.is_family_revoked(claims.family_id):
        raise unauthorized()
    # <= because a password change and a stolen token can fall in the same second.
    if claims.issued_at <= await store.tokens_valid_after(claims.user_id):
        raise unauthorized()
    return claims


ClaimsDep = Annotated[AccessClaims, Depends(current_claims)]
