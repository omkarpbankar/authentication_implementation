"""App 6: an app in a single sign-on group, with provisioning and back-channel logout.

Run:  uv run uvicorn apps.app6_sso.oidc_app:app --port 8006
"""

import secrets
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from redis.asyncio import Redis

from apps.app2_oidc.oidc import OidcProvider, TokenError, new_pkce_pair
from apps.app2_oidc.sessions import SessionStore
from apps.app6_sso import scim
from apps.app6_sso.directory import Directory
from apps.app6_sso.settings import settings

app = FastAPI(title="App 6: SSO with OIDC")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
default_provider = OidcProvider(settings.issuer)

SESSION_COOKIE = "app6_session"
STATE_COOKIE = "app6_login_state"
LOGOUT_TOKEN_MAX_AGE_SECONDS = 600


def get_provider() -> OidcProvider:
    return default_provider


def get_store() -> SessionStore:
    return SessionStore(redis_client, 3600)


def get_directory() -> Directory:
    return Directory(redis_client)


ProviderDep = Annotated[OidcProvider, Depends(get_provider)]
StoreDep = Annotated[SessionStore, Depends(get_store)]
DirectoryDep = Annotated[Directory, Depends(get_directory)]
SessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE)]


def get_end_sessions(store: StoreDep, directory: DirectoryDep):
    async def end_sessions(username: str) -> None:
        for session_id in await directory.sessions_for_user(username):
            await store.delete(session_id)

    return end_sessions


app.dependency_overrides[scim.get_directory] = get_directory
app.dependency_overrides[scim.get_end_sessions] = get_end_sessions
app.include_router(scim.router)


def redirect_uri() -> str:
    return f"{settings.base_url}/callback"


def provider_for_email(email: str) -> str | None:
    """Home realm discovery: the email domain says which company's login to use."""
    return settings.sso_domains.get(email.rpartition("@")[2].lower())


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <h1>App 6</h1>
    <form method="post" action="/start">
      <input name="email" placeholder="you@acme.example">
      <button>Continue</button>
    </form>
    <p><a href="/silent">Try silent SSO</a></p>
    """


async def begin_login(
    store: SessionStore, provider: OidcProvider, extra: str = ""
) -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce_pair()
    await store.save_login_attempt(state, verifier, nonce, "/profile")
    url = await provider.authorization_url(
        settings.client_id, redirect_uri(), state, nonce, challenge, "openid profile email"
    )
    response = RedirectResponse(url + extra, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(STATE_COOKIE, state, httponly=True, samesite="lax", max_age=300)
    return response


@app.post("/start")
async def start(
    email: Annotated[str, Form()], store: StoreDep, provider: ProviderDep
) -> RedirectResponse:
    if provider_for_email(email) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No single sign-on for this email domain")
    return await begin_login(store, provider)


@app.get("/login")
async def login(store: StoreDep, provider: ProviderDep) -> RedirectResponse:
    return await begin_login(store, provider)


@app.get("/silent")
async def silent(store: StoreDep, provider: ProviderDep) -> RedirectResponse:
    # prompt=none means: sign in only if an IdP session exists, and never show a login page.
    return await begin_login(store, provider, extra="&prompt=none")


@app.get("/callback")
async def callback(
    store: StoreDep,
    provider: ProviderDep,
    directory: DirectoryDep,
    code: str = "",
    state: str = "",
    error: str = "",
    state_cookie: Annotated[str | None, Cookie(alias=STATE_COOKIE)] = None,
) -> Response:
    if not state or not state_cookie or not secrets.compare_digest(state, state_cookie):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login state does not match")
    attempt = await store.take_login_attempt(state)
    if attempt is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login attempt expired or already used")
    if error == "login_required":
        return RedirectResponse("/?silent=failed", status_code=status.HTTP_303_SEE_OTHER)

    try:
        tokens = await provider.exchange_code(
            code, attempt["verifier"], settings.client_id, settings.client_secret, redirect_uri()
        )
        claims = await provider.validate_id_token(
            tokens["id_token"], settings.client_id, attempt["nonce"]
        )
    except TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login could not be completed") from exc

    username = claims.get("email") or claims["sub"]
    user = await directory.provision_on_login(username, claims.get("name", ""))
    if not user["active"]:
        # A valid SSO login is not enough, because the directory has switched this user off.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your account has been deactivated")

    session_id = await store.create({"user": user, "idp_sid": claims.get("sid", "")})
    await directory.remember_session(username, session_id, claims.get("sid", ""))
    response = RedirectResponse("/profile", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    response.delete_cookie(STATE_COOKIE)
    return response


@app.get("/profile")
async def profile(store: StoreDep, session_id: SessionCookie = None) -> dict:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    return session["user"]


@app.post("/backchannel-logout")
async def backchannel_logout(
    logout_token: Annotated[str, Form()],
    provider: ProviderDep,
    store: StoreDep,
    directory: DirectoryDep,
) -> Response:
    """The IdP calls this directly, server to server, when a user signs out elsewhere."""
    try:
        claims = await provider.validate_logout_token(logout_token, settings.client_id)
    except TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid logout token") from exc

    if not await directory.first_use(claims.get("jti", logout_token)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Logout token already used")

    for session_id in await directory.sessions_for_idp_sid(claims.get("sid", "")):
        await store.delete(session_id)
    return Response(status_code=status.HTTP_200_OK)
