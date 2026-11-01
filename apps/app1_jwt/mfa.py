"""Two-step login with authenticator app codes, recovery codes, and step-up checks."""

import hashlib
import secrets
import time
from typing import Annotated

import pyotp
import segno
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from apps.app1_jwt.deps import ClaimsDep, KeyRingDep, StoreDep, TokenPair, issue_pair
from apps.app1_jwt.settings import settings
from apps.app1_jwt.tokens import AccessClaims

router = APIRouter(tags=["MFA"])
fernet = Fernet(settings.mfa_encryption_key)

RECOVERY_CODE_COUNT = 10
MAX_ATTEMPTS = 5
PERIOD_SECONDS = 30


class MfaChallenge(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class CodeRequest(BaseModel):
    code: str


class MfaLogin(BaseModel):
    mfa_token: str
    code: str = ""
    recovery_code: str = ""


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def matching_step(secret: str, code: str) -> int | None:
    """Returns which 30-second window a code belongs to, allowing one step of clock drift."""
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // PERIOD_SECONDS
    for step in (current - 1, current, current + 1):
        if secrets.compare_digest(totp.at(step * PERIOD_SECONDS), code):
            return step
    return None


@router.post("/mfa/totp/enroll")
async def enroll(claims: ClaimsDep, store: StoreDep) -> dict:
    existing = await store.get_mfa(claims.user_id)
    if existing and existing["enabled"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    secret = pyotp.random_base32()
    user = await store.get_user_by_id(claims.user_id)
    # Encrypted at rest, because a stolen database must not let attackers generate codes.
    await store.set_mfa(
        claims.user_id,
        {"secret": fernet.encrypt(secret.encode()).decode(), "enabled": False, "recovery": []},
    )
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="Auth Course")
    return {"secret": secret, "uri": uri, "qr_svg": segno.make(uri).svg_inline(scale=4)}


@router.post("/mfa/totp/confirm")
async def confirm(body: CodeRequest, claims: ClaimsDep, store: StoreDep) -> dict:
    record = await store.get_mfa(claims.user_id)
    if record is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start enrollment first")
    secret = fernet.decrypt(record["secret"].encode()).decode()
    # Enrollment only finishes once a real code proves the phone has the secret.
    if matching_step(secret, body.code) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not correct")

    codes = [secrets.token_hex(5) for _ in range(RECOVERY_CODE_COUNT)]
    record["enabled"] = True
    record["recovery"] = [hash_code(code) for code in codes]
    await store.set_mfa(claims.user_id, record)
    # This is the only time the codes are shown. Only hashes are stored.
    return {"recovery_codes": codes}


@router.post("/auth/login/mfa")
async def finish_login(body: MfaLogin, store: StoreDep, ring: KeyRingDep) -> TokenPair:
    ticket = await store.read_mfa_ticket(body.mfa_token)
    if ticket is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in again")
    if ticket["attempts"] >= MAX_ATTEMPTS:
        # A six-digit code has only a million values, so guesses must be limited.
        await store.end_mfa_ticket(body.mfa_token)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts")

    user_id = ticket["user_id"]
    record = await store.get_mfa(user_id)
    passed = False
    if body.recovery_code:
        hashed = hash_code(body.recovery_code)
        if hashed in record["recovery"]:
            # Removed on use, so each recovery code works exactly once.
            record["recovery"].remove(hashed)
            await store.set_mfa(user_id, record)
            passed = True
    elif body.code:
        secret = fernet.decrypt(record["secret"].encode()).decode()
        step = matching_step(secret, body.code)
        passed = step is not None and await store.claim_totp_step(user_id, step)

    if not passed:
        await store.count_mfa_attempt(body.mfa_token, ticket)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not correct")

    await store.end_mfa_ticket(body.mfa_token)
    await store.mark_recent_mfa(user_id)
    return await issue_pair(store, ring, user_id)


@router.post("/mfa/verify")
async def step_up(body: CodeRequest, claims: ClaimsDep, store: StoreDep) -> dict[str, str]:
    """Confirm a code again before a sensitive action."""
    record = await store.get_mfa(claims.user_id)
    if record is None or not record["enabled"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enabled")
    secret = fernet.decrypt(record["secret"].encode()).decode()
    step = matching_step(secret, body.code)
    if step is None or not await store.claim_totp_step(claims.user_id, step):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not correct")
    await store.mark_recent_mfa(claims.user_id)
    return {"message": "Verified for the next five minutes"}


async def recent_mfa(claims: ClaimsDep, store: StoreDep) -> AccessClaims:
    if not await store.has_recent_mfa(claims.user_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Confirm your MFA code first")
    return claims


@router.post("/account/close-preview")
async def sensitive_action(claims: Annotated[AccessClaims, Depends(recent_mfa)]) -> dict[str, str]:
    """Stands in for any high-risk action, such as closing an account."""
    return {"message": "Step-up check passed"}
