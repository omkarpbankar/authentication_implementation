"""App 5: one account, several third-party logins.

Works straight away with the local Keycloak. Google, Microsoft, and GitHub appear once you add
their client IDs. See SETUP.md.
Run:  uv run uvicorn apps.app5_social.main:app --port 8005
"""

import secrets
import time
from html import escape
from typing import Annotated

import httpx
from cryptography.fernet import Fernet
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from redis.asyncio import Redis

from apps.app2_oidc.oidc import TokenError, new_pkce_pair
from apps.app5_social.accounts import AccountExists, Accounts, IdentityTaken, LastLoginMethod
from apps.app5_social.providers import Adapter, build_registry
from apps.app5_social.settings import settings

app = FastAPI(title="App 5: third-party login")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
default_registry = build_registry(settings)
fernet = Fernet(settings.token_encryption_key)

SESSION_COOKIE = "app5_session"
STATE_COOKIE = "app5_login_state"
CALENDAR_SCOPE = "openid email https://www.googleapis.com/auth/calendar.readonly"
CALENDAR_URL = "https://www.googleapis.com/calendar/v3/calendars/primary/events?maxResults=5"


def get_accounts() -> Accounts:
    return Accounts(redis_client, settings.session_ttl_seconds)


def get_registry() -> dict[str, Adapter]:
    return default_registry


AccountsDep = Annotated[Accounts, Depends(get_accounts)]
RegistryDep = Annotated[dict[str, Adapter], Depends(get_registry)]
SessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE)]
StateCookie = Annotated[str | None, Cookie(alias=STATE_COOKIE)]


def callback_url(provider: str) -> str:
    return f"{settings.base_url}/callback/{provider}"


def adapter_for(registry: dict[str, Adapter], provider: str) -> Adapter:
    adapter = registry.get(provider)
    if adapter is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider")
    return adapter


async def start_flow(
    accounts: Accounts, adapter: Adapter, mode: str, user_id: str = "", extra: dict | None = None
) -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce_pair()
    await accounts.save_attempt(
        state,
        {
            "provider": adapter.name,
            "verifier": verifier,
            "nonce": nonce,
            "mode": mode,
            "user_id": user_id,
        },
    )
    url = await adapter.authorize_url(callback_url(adapter.name), state, nonce, challenge, extra)
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(STATE_COOKIE, state, httponly=True, samesite="lax", max_age=300)
    return response


async def required_session(accounts: AccountsDep, session_id: SessionCookie = None) -> dict:
    session = await accounts.session(session_id)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    return session


SessionDep = Annotated[dict, Depends(required_session)]


def check_csrf(session: dict, token: str) -> None:
    if not secrets.compare_digest(token, session["csrf_token"]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")


@app.get("/", response_class=HTMLResponse)
def home(registry: RegistryDep) -> str:
    links = "".join(
        f'<li><a href="/login/{escape(name)}">Sign in with {escape(name.title())}</a></li>'
        for name in sorted(registry)
    )
    return f"<h1>App 5</h1><ul>{links}</ul>"


@app.get("/login/{provider}")
async def login(provider: str, accounts: AccountsDep, registry: RegistryDep) -> RedirectResponse:
    return await start_flow(accounts, adapter_for(registry, provider), "login")


@app.post("/link/{provider}")
async def link(
    provider: str,
    accounts: AccountsDep,
    registry: RegistryDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    check_csrf(session, csrf_token)
    # Someone at an unlocked laptop must not be able to attach their own login.
    if time.time() - session["authenticated_at"] > settings.reauth_window_seconds:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Please sign in again before linking")
    return await start_flow(
        accounts, adapter_for(registry, provider), "link", user_id=session["user_id"]
    )


@app.post("/unlink/{provider}")
async def unlink(
    provider: str,
    accounts: AccountsDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()] = "",
) -> dict[str, str]:
    check_csrf(session, csrf_token)
    try:
        await accounts.unlink(session["user_id"], provider)
    except LastLoginMethod as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "You cannot remove your only way to sign in"
        ) from exc
    return {"message": "Unlinked"}


@app.get("/callback/{provider}")
async def callback(
    provider: str,
    accounts: AccountsDep,
    registry: RegistryDep,
    code: str = "",
    state: str = "",
    state_cookie: StateCookie = None,
) -> RedirectResponse:
    if not state or not state_cookie or not secrets.compare_digest(state, state_cookie):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login state does not match")

    attempt = await accounts.take_attempt(state)
    # The provider must match, or a response from one provider could pose as another.
    if attempt is None or attempt["provider"] != provider:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login attempt expired or invalid")

    adapter = adapter_for(registry, provider)
    try:
        profile, tokens = await adapter.finish(
            code, attempt["verifier"], attempt["nonce"], callback_url(provider)
        )
    except TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login could not be completed") from exc

    if attempt["mode"] == "calendar":
        # Refresh tokens give long-term access to a user's data, so encrypt them at rest.
        encrypted = fernet.encrypt(tokens["refresh_token"].encode()).decode()
        await accounts.save_provider_token(attempt["user_id"], provider, encrypted)
        return RedirectResponse("/account", status_code=status.HTTP_303_SEE_OTHER)

    if attempt["mode"] == "link":
        try:
            await accounts.link(attempt["user_id"], profile)
        except IdentityTaken as exc:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "That login belongs to another account"
            ) from exc
        response = RedirectResponse("/account", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(STATE_COOKIE)
        return response

    try:
        user_id = await accounts.sign_in(profile)
    except AccountExists as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "An account with this email exists. Sign in the usual way, then link this login.",
        ) from exc

    response = RedirectResponse("/account", status_code=status.HTTP_303_SEE_OTHER)
    session_id = await accounts.create_session(user_id)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    response.delete_cookie(STATE_COOKIE)
    return response


@app.get("/account")
async def account(accounts: AccountsDep, session: SessionDep) -> dict:
    user_id = session["user_id"]
    user = await accounts.user(user_id)
    return {
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "logins": sorted(await accounts.identities(user_id)),
        "csrf_token": session["csrf_token"],
    }


@app.post("/calendar/connect")
async def connect_calendar(
    accounts: AccountsDep,
    registry: RegistryDep,
    session: SessionDep,
    csrf_token: Annotated[str, Form()] = "",
) -> RedirectResponse:
    check_csrf(session, csrf_token)
    # Incremental consent: ask for calendar access only when the user wants that feature.
    return await start_flow(
        accounts,
        adapter_for(registry, "google"),
        "calendar",
        user_id=session["user_id"],
        extra={
            "scope": CALENDAR_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
        },
    )


@app.get("/calendar/events")
async def calendar_events(
    accounts: AccountsDep, registry: RegistryDep, session: SessionDep
) -> dict:
    encrypted = await accounts.provider_token(session["user_id"], "google")
    if encrypted is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Calendar is not connected")
    refresh_token = fernet.decrypt(encrypted.encode()).decode()
    tokens = await adapter_for(registry, "google").refresh(refresh_token)
    async with httpx.AsyncClient(timeout=10) as http:
        response = await http.get(
            CALENDAR_URL, headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
    if response.status_code != 200:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Google refused the request")
    return {"events": [item.get("summary", "") for item in response.json().get("items", [])]}


@app.post("/logout")
async def logout(accounts: AccountsDep, session_id: SessionCookie = None) -> RedirectResponse:
    if session_id:
        await accounts.end_session(session_id)
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response
