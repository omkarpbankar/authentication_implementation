"""App 1: first-party login with JWT access tokens and rotating refresh tokens.

Run:  uv run uvicorn apps.app1_jwt.main:app --port 8001
Docs: http://localhost:8001/docs
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from apps.app1_jwt import api_keys, links, mfa, passkeys
from apps.app1_jwt.deps import (
    DUMMY_HASH,
    ClaimsDep,
    KeyRingDep,
    StoreDep,
    TokenPair,
    get_key_ring,  # noqa: F401  Tests override this.
    get_store,  # noqa: F401  Tests override this.
    issue_pair,
    password_hash,
    unauthorized,
)
from apps.shared.hardening import apply_hardening
from apps.shared.rate_limit import RateLimiter, client_ip

app = FastAPI(title="App 1: JWT authentication")
apply_hardening(app)
for extra in (mfa.router, passkeys.router, links.router, api_keys.router):
    app.include_router(extra)


class Credentials(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+$", max_length=254)
    password: str = Field(min_length=12, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/register", status_code=status.HTTP_202_ACCEPTED)
async def register(body: Credentials, store: StoreDep) -> dict[str, str]:
    await store.create_user(body.email.lower(), password_hash.hash(body.password))
    # The same reply either way, so sign-up cannot be used to discover who has an account.
    return {"message": "If this email is new, the account has been created."}


async def limit_login(request: Request, store: StoreDep, email: str) -> None:
    """Slows guessing without locking anyone out.

    A hard lockout would let an attacker block a real user just by failing on purpose. Limits
    here reset on their own, and the tightest one also needs the attacker's own address.
    """
    limiter = RateLimiter(store.redis)
    ip = client_ip(request)
    limits = (
        (f"login:ip:{ip}", 60),
        (f"login:account:{email}", 100),
        (f"login:pair:{ip}:{email}", 10),
    )
    for key, limit in limits:
        if not await limiter.allow(key, limit, 60):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many attempts. Please wait a minute.",
                headers={"Retry-After": "60"},
            )


@app.post("/auth/login")
async def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    store: StoreDep,
    ring: KeyRingDep,
) -> TokenPair | mfa.MfaChallenge:
    await limit_login(request, store, form.username.lower())
    user = await store.get_user_by_email(form.username.lower())
    password_ok = password_hash.verify(form.password, user["password_hash"] if user else DUMMY_HASH)
    if user is None or not password_ok:
        raise unauthorized("Invalid email or password")
    record = await store.get_mfa(user["id"])
    if record and record["enabled"]:
        # A correct password earns only a short ticket to the second step, never tokens.
        return mfa.MfaChallenge(mfa_token=await store.new_mfa_ticket(user["id"]))
    return await issue_pair(store, ring, user["id"])


@app.post("/auth/refresh")
async def refresh(body: RefreshRequest, store: StoreDep, ring: KeyRingDep) -> TokenPair:
    record = await store.get_refresh_token(body.refresh_token)
    if record is None or await store.is_family_revoked(record["family_id"]):
        raise unauthorized()

    if not await store.claim_refresh_token(body.refresh_token):
        # An old token came back. We cannot tell the user from a thief, so end the family.
        await store.revoke_family(record["family_id"])
        raise unauthorized()

    return await issue_pair(store, ring, record["user_id"], record["family_id"])


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(claims: ClaimsDep, store: StoreDep) -> None:
    await store.revoke_family(claims.family_id)
    await store.deny_access_token(claims.jti, claims.expires_at)


@app.get("/sessions")
async def list_sessions(claims: ClaimsDep, store: StoreDep) -> list[dict]:
    """Every device this account is signed in on."""
    sessions = await store.active_sessions(claims.user_id)
    return [{**session, "current": session["id"] == claims.family_id} for session in sessions]


@app.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def end_session(session_id: str, claims: ClaimsDep, store: StoreDep) -> None:
    # Someone else's session looks the same as a missing one.
    if not await store.revoke_session(claims.user_id, session_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")


@app.get("/users/me")
async def me(claims: ClaimsDep, store: StoreDep) -> dict[str, str]:
    user = await store.get_user_by_id(claims.user_id)
    if user is None:
        raise unauthorized()
    return {"id": user["id"], "email": user["email"]}


@app.get("/.well-known/jwks.json")
def jwks(ring: KeyRingDep) -> dict:
    return ring.jwks()
