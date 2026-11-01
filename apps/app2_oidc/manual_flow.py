"""App 2: Authorization Code + PKCE written by hand, with a Backend-for-Frontend session.

Run:  uv run uvicorn apps.app2_oidc.manual_flow:app --port 8002
Sign in with asha / correct-horse-battery.
"""

import secrets
import time
from html import escape
from typing import Annotated
from urllib.parse import urlencode

from fastapi import Cookie, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from redis.asyncio import Redis

from apps.app2_oidc.oidc import OidcProvider, TokenError, new_pkce_pair
from apps.app2_oidc.sessions import SessionStore
from apps.app2_oidc.settings import settings

app = FastAPI(title="App 2: OIDC by hand")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
default_provider = OidcProvider(settings.issuer)

SESSION_COOKIE = "app2_session"
STATE_COOKIE = "app2_login_state"
SCOPE = "openid profile email"
REFRESH_MARGIN_SECONDS = 15


def get_store() -> SessionStore:
    return SessionStore(redis_client, settings.session_ttl_seconds)


def get_provider() -> OidcProvider:
    return default_provider


StoreDep = Annotated[SessionStore, Depends(get_store)]
ProviderDep = Annotated[OidcProvider, Depends(get_provider)]
SessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE)]
StateCookie = Annotated[str | None, Cookie(alias=STATE_COOKIE)]


def redirect_uri() -> str:
    return f"{settings.base_url}/callback"


def safe_next(path: str) -> str:
    # Only local paths are allowed, otherwise login could send users to an attacker's site.
    if path.startswith("/") and not path.startswith(("//", "/\\")):
        return path
    return "/"


def set_cookie(response: Response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name,
        value,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=max_age,
    )


@app.get("/", response_class=HTMLResponse)
async def home(store: StoreDep, session_id: SessionCookie = None) -> str:
    session = await store.get(session_id)
    if session is None:
        return '<h1>App 2</h1><p>You are signed out.</p><a href="/login">Sign in</a>'
    name = escape(session["user"].get("name", "unknown"))
    return f"""
    <h1>App 2</h1>
    <p>Signed in as <b>{name}</b>.</p>
    <p><a href="/profile">Profile</a></p>
    <form method="post" action="/logout"><button>Sign out</button></form>
    """


@app.get("/login")
async def login(
    store: StoreDep, provider: ProviderDep, next_path: Annotated[str, Query(alias="next")] = "/"
) -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce_pair()

    await store.save_login_attempt(state, verifier, nonce, safe_next(next_path))
    url = await provider.authorization_url(
        settings.client_id, redirect_uri(), state, nonce, challenge, SCOPE
    )
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    # The cookie binds this attempt to this browser. Without it, an attacker could finish a
    # login they started themselves in a victim's browser, which is login CSRF.
    set_cookie(response, STATE_COOKIE, state, 300)
    return response


@app.get("/callback")
async def callback(
    store: StoreDep,
    provider: ProviderDep,
    code: str = "",
    state: str = "",
    error: str = "",
    state_cookie: StateCookie = None,
) -> RedirectResponse:
    if error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The login server reported an error")
    if not state or not state_cookie or not secrets.compare_digest(state, state_cookie):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login state does not match")

    attempt = await store.take_login_attempt(state)
    if attempt is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login attempt expired or already used")

    try:
        tokens = await provider.exchange_code(
            code, attempt["verifier"], settings.client_id, settings.client_secret, redirect_uri()
        )
        claims = await provider.validate_id_token(
            tokens["id_token"], settings.client_id, attempt["nonce"]
        )
    except TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login could not be completed") from exc

    session_id = await store.create(
        {
            "user": {
                "sub": claims["sub"],
                "name": claims.get("preferred_username", ""),
                "email": claims.get("email", ""),
            },
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens["id_token"],
            "expires_at": int(time.time()) + int(tokens.get("expires_in", 60)),
        }
    )
    response = RedirectResponse(attempt["next"], status_code=status.HTTP_303_SEE_OTHER)
    set_cookie(response, SESSION_COOKIE, session_id, settings.session_ttl_seconds)
    response.delete_cookie(STATE_COOKIE)
    return response


async def fresh_session(
    request: Request, store: StoreDep, provider: ProviderDep, session_id: SessionCookie = None
) -> dict:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")

    if session["expires_at"] - REFRESH_MARGIN_SECONDS < time.time():
        try:
            tokens = await provider.refresh(
                session["refresh_token"], settings.client_id, settings.client_secret
            )
        except TokenError as exc:
            # The login server has ended this session, so ours ends too.
            await store.delete(session_id)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session ended") from exc
        session["access_token"] = tokens["access_token"]
        session["refresh_token"] = tokens.get("refresh_token", session["refresh_token"])
        session["expires_at"] = int(time.time()) + int(tokens.get("expires_in", 60))
        await store.update(session_id, session)
    return session


@app.get("/profile")
async def profile(session: Annotated[dict, Depends(fresh_session)]) -> dict:
    # Returns the user, never the tokens, which is the whole point of this pattern.
    return session["user"]


@app.post("/logout")
async def logout(
    store: StoreDep, provider: ProviderDep, session_id: SessionCookie = None
) -> RedirectResponse:
    session = await store.get(session_id)
    target = "/"
    if session:
        await store.delete(session_id)
        metadata = await provider.metadata()
        query = urlencode(
            {
                "id_token_hint": session["id_token"],
                "post_logout_redirect_uri": f"{settings.base_url}/",
            }
        )
        # Ending only our session would leave the login server signed in.
        target = f"{metadata['end_session_endpoint']}?{query}"
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response
