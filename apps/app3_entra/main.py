"""App 3: sign in with Microsoft Entra ID, using MSAL.

Needs your own tenant. See SETUP.md first.
Run:  uv run uvicorn apps.app3_entra.main:app --port 8003
"""

import asyncio
import json
import secrets
from html import escape
from typing import Annotated
from urllib.parse import urlencode

import msal
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from redis.asyncio import Redis

from apps.app2_oidc.sessions import SessionStore
from apps.app3_entra.settings import settings

app = FastAPI(title="App 3: Entra ID sign-in")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)

SESSION_COOKIE = "app3_session"
STATE_COOKIE = "app3_login_state"
FLOW_TTL_SECONDS = 300


def get_msal() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        settings.web_client_id,
        authority=settings.authority,
        client_credential=settings.web_client_secret,
    )


def get_store() -> SessionStore:
    return SessionStore(redis_client, 3600)


MsalDep = Annotated[msal.ConfidentialClientApplication, Depends(get_msal)]
StoreDep = Annotated[SessionStore, Depends(get_store)]


def redirect_uri() -> str:
    return f"{settings.base_url}/callback"


@app.get("/", response_class=HTMLResponse)
async def home(
    store: StoreDep,
    session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> str:
    session = await store.get(session_id)
    if session is None:
        return '<h1>App 3</h1><a href="/login">Sign in with Microsoft</a>'
    return f"""
    <h1>App 3</h1>
    <p>Signed in as <b>{escape(session["user"]["name"])}</b>.</p>
    <a href="/profile">Profile</a>
    <form method="post" action="/logout"><button>Sign out</button></form>
    """


@app.get("/login")
async def login(client: MsalDep, store: StoreDep) -> RedirectResponse:
    # MSAL creates the state, nonce, and PKCE values for you.
    flow = await asyncio.to_thread(
        client.initiate_auth_code_flow, [settings.api_scope], redirect_uri=redirect_uri()
    )
    await store.redis.set(f"flow:{flow['state']}", json.dumps(flow), ex=FLOW_TTL_SECONDS)
    response = RedirectResponse(flow["auth_uri"], status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(STATE_COOKIE, flow["state"], httponly=True, samesite="lax", max_age=300)
    return response


@app.get("/callback")
async def callback(
    request: Request,
    client: MsalDep,
    store: StoreDep,
    state_cookie: Annotated[str | None, Cookie(alias=STATE_COOKIE)] = None,
) -> RedirectResponse:
    state = request.query_params.get("state", "")
    if not state or not state_cookie or not secrets.compare_digest(state, state_cookie):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login state does not match")

    raw_flow = await store.redis.getdel(f"flow:{state}")
    if raw_flow is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login attempt expired or already used")

    result = await asyncio.to_thread(
        client.acquire_token_by_auth_code_flow,
        json.loads(raw_flow),
        dict(request.query_params),
    )
    if "error" in result or "id_token_claims" not in result:
        # AADSTS50105 here means the user is not assigned to this application.
        raise HTTPException(status.HTTP_403_FORBIDDEN, result.get("error", "Login failed"))

    claims = result["id_token_claims"]
    session_id = await store.create(
        {
            "user": {
                # oid plus tid is stable. Emails and names can change.
                "id": f"{claims['tid']}:{claims['oid']}",
                "name": claims.get("name", ""),
                "username": claims.get("preferred_username", ""),
            },
            "access_token": result.get("access_token", ""),
        }
    )
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    response.delete_cookie(STATE_COOKIE)
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


@app.post("/logout")
async def logout(
    store: StoreDep,
    session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> RedirectResponse:
    if session_id:
        await store.delete(session_id)
    query = urlencode({"post_logout_redirect_uri": f"{settings.base_url}/"})
    target = f"{settings.authority}/oauth2/v2.0/logout?{query}"
    response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SESSION_COOKIE)
    return response
