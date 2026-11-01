"""The same login as manual_flow.py, using Authlib. Compare the two files.

Authlib handles state, nonce, PKCE, the code exchange, and ID token checks. Real apps should
use a library like this. The hand-written version exists so you know what it does for you.

Run:  uv run uvicorn apps.app2_oidc.library_flow:app --port 8012
"""

import secrets
from typing import Annotated

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from redis.asyncio import Redis
from starlette.middleware.sessions import SessionMiddleware

from apps.app2_oidc.sessions import SessionStore
from apps.app2_oidc.settings import settings

BASE_URL = "http://localhost:8012"
SESSION_COOKIE = "app2_lib_session"

app = FastAPI(title="App 2: OIDC with Authlib")
# This cookie is signed but not encrypted, so it may only hold short-lived login values.
# The tokens themselves go in Redis.
app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(32), same_site="lax")

oauth = OAuth()
oauth.register(
    "keycloak",
    client_id=settings.client_id,
    client_secret=settings.client_secret,
    server_metadata_url=f"{settings.issuer}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def get_store() -> SessionStore:
    return SessionStore(redis_client, settings.session_ttl_seconds)


StoreDep = Annotated[SessionStore, Depends(get_store)]


@app.get("/login")
async def login(request: Request):
    return await oauth.keycloak.authorize_redirect(request, f"{BASE_URL}/callback")


@app.get("/callback")
async def callback(request: Request, store: StoreDep) -> RedirectResponse:
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login could not be completed") from exc

    user = token["userinfo"]
    session_id = await store.create(
        {
            "user": {"sub": user["sub"], "name": user.get("preferred_username", "")},
            "access_token": token["access_token"],
            "refresh_token": token.get("refresh_token", ""),
        }
    )
    response = RedirectResponse("/profile", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SESSION_COOKIE, session_id, httponly=True, samesite="lax", secure=settings.cookie_secure
    )
    return response


@app.get("/profile")
async def profile(
    store: StoreDep,
    session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> dict:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    return session["user"]
