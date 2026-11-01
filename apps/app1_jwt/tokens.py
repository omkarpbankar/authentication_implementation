import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass

import jwt

from apps.app1_jwt.keys import KeyRing

ALGORITHMS = ["RS256"]  # Fixed here, because the token's own header cannot be trusted.
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]


class InvalidToken(Exception):
    pass


@dataclass(frozen=True)
class AccessClaims:
    user_id: str
    jti: str
    family_id: str
    expires_at: int
    issued_at: int


def create_access_token(
    ring: KeyRing, user_id: str, family_id: str, issuer: str, audience: str, ttl_seconds: int
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": user_id,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "fid": family_id,
        "typ": "access",
    }
    return jwt.encode(payload, ring.active_key, algorithm="RS256", headers={"kid": ring.active_kid})


def verify_access_token(token: str, ring: KeyRing, issuer: str, audience: str) -> AccessClaims:
    try:
        # Another process may have rotated or retired a key since the last request.
        ring.sync()
        kid = jwt.get_unverified_header(token).get("kid", "")
        key = ring.public_key(kid)
        if key is None:
            raise InvalidToken("Unknown signing key")

        payload = jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            audience=audience,
            issuer=issuer,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc)) from exc

    if payload.get("typ") != "access":
        raise InvalidToken("Not an access token")
    return AccessClaims(
        payload["sub"], payload["jti"], payload.get("fid", ""), payload["exp"], payload["iat"]
    )


def new_refresh_token() -> str:
    # Opaque and random, so all its state stays on the server, where it can be revoked.
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    # A fast hash is fine here, as the input is long and random, unlike a human password.
    return hashlib.sha256(token.encode()).hexdigest()
