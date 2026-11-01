"""App 4: customer sign-up and sign-in with Amazon Cognito.

Needs your own AWS account. See SETUP.md first.
Run:  uv run uvicorn apps.app4_cognito.main:app --port 8004
"""

import secrets
from typing import Annotated
from urllib.parse import urlencode

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis

from apps.app2_oidc.oidc import OidcProvider, TokenError, new_pkce_pair
from apps.app2_oidc.sessions import SessionStore
from apps.app4_cognito.custom_ui import CognitoUsers, SignInFailed
from apps.app4_cognito.settings import settings
from apps.app4_cognito.tokens import CognitoTokenValidator, groups, scopes

app = FastAPI(title="App 4: Amazon Cognito")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
bearer = HTTPBearer(auto_error=False)
default_provider = OidcProvider(settings.issuer)

SESSION_COOKIE = "app4_session"
STATE_COOKIE = "app4_login_state"
SCOPE = "openid email profile"


def get_provider() -> OidcProvider:
    return default_provider


def get_validator(
    provider: Annotated[OidcProvider, Depends(get_provider)],
) -> CognitoTokenValidator:
    return CognitoTokenValidator(provider, {settings.client_id, settings.m2m_client_id})


def get_store() -> SessionStore:
    return SessionStore(redis_client, 3600)


def get_users() -> CognitoUsers:
    return CognitoUsers(settings.client_id, settings.client_secret, settings.region)


ProviderDep = Annotated[OidcProvider, Depends(get_provider)]
ValidatorDep = Annotated[CognitoTokenValidator, Depends(get_validator)]
StoreDep = Annotated[SessionStore, Depends(get_store)]
UsersDep = Annotated[CognitoUsers, Depends(get_users)]
SessionCookie = Annotated[str | None, Cookie(alias=SESSION_COOKIE)]


def redirect_uri() -> str:
    return f"{settings.base_url}/callback"


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return '<h1>App 4</h1><a href="/login">Sign in with Cognito managed login</a>'


@app.get("/login")
async def login(store: StoreDep, provider: ProviderDep) -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce_pair()
    await store.save_login_attempt(state, verifier, nonce, "/")
    url = await provider.authorization_url(
        settings.client_id, redirect_uri(), state, nonce, challenge, SCOPE
    )
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(STATE_COOKIE, state, httponly=True, samesite="lax", max_age=300)
    return response


async def open_session(store: StoreDep, validator: ValidatorDep, tokens: dict, nonce: str) -> str:
    claims = await validator.validate_id_token(tokens["IdToken"], settings.client_id)
    if nonce and not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise TokenError("Nonce mismatch")
    return await store.create(
        {
            "user": {"sub": claims["sub"], "email": claims.get("email", "")},
            "access_token": tokens["AccessToken"],
        }
    )


@app.get("/callback")
async def callback(
    store: StoreDep,
    provider: ProviderDep,
    validator: ValidatorDep,
    code: str = "",
    state: str = "",
    state_cookie: Annotated[str | None, Cookie(alias=STATE_COOKIE)] = None,
) -> RedirectResponse:
    if not state or not state_cookie or not secrets.compare_digest(state, state_cookie):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login state does not match")
    attempt = await store.take_login_attempt(state)
    if attempt is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login attempt expired or already used")

    try:
        tokens = await provider.exchange_code(
            code, attempt["verifier"], settings.client_id, settings.client_secret, redirect_uri()
        )
        session_id = await open_session(
            store,
            validator,
            {"IdToken": tokens["id_token"], "AccessToken": tokens["access_token"]},
            attempt["nonce"],
        )
    except TokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Login could not be completed") from exc

    response = RedirectResponse("/profile", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    response.delete_cookie(STATE_COOKIE)
    return response


@app.post("/signup", status_code=status.HTTP_202_ACCEPTED)
def signup(
    users: UsersDep,
    email: Annotated[str, Form()],
    password: Annotated[str, Form(min_length=12)],
) -> dict:
    users.sign_up(email, password)
    return {"message": "Check your email for a confirmation code."}


@app.post("/signup/confirm")
def confirm(
    users: UsersDep, email: Annotated[str, Form()], code: Annotated[str, Form()]
) -> dict[str, str]:
    users.confirm(email, code)
    return {"message": "Account confirmed. You can sign in."}


@app.post("/signin")
async def signin(
    users: UsersDep,
    store: StoreDep,
    validator: ValidatorDep,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> RedirectResponse:
    try:
        session_id = await open_session(store, validator, users.sign_in(email, password), "")
    except SignInFailed as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password") from exc
    response = RedirectResponse("/profile", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    return response


@app.get("/profile")
async def profile(store: StoreDep, session_id: SessionCookie = None) -> dict:
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    return session["user"]


@app.post("/logout")
async def logout(store: StoreDep, session_id: SessionCookie = None) -> RedirectResponse:
    if session_id:
        await store.delete(session_id)
    # Cognito uses its own logout endpoint, not the standard OIDC end-session one.
    query = urlencode({"client_id": settings.client_id, "logout_uri": f"{settings.base_url}/"})
    response = RedirectResponse(
        f"{settings.domain}/logout?{query}", status_code=status.HTTP_303_SEE_OTHER
    )
    response.delete_cookie(SESSION_COOKIE)
    return response


async def access_claims(
    validator: ValidatorDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        return await validator.validate_access_token(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc


ClaimsDep = Annotated[dict, Depends(access_claims)]


@app.get("/api/members")
def members_area(claims: ClaimsDep) -> dict:
    if not groups(claims) & {"member", "admin"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Members only")
    return {"plan": claims.get("plan", "unknown")}


@app.delete("/api/members/{member_id}")
def remove_member(member_id: str, claims: ClaimsDep) -> dict:
    if "admin" not in groups(claims):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admins only")
    return {"removed": member_id}


@app.get("/api/orders")
def machine_orders(claims: ClaimsDep) -> dict:
    # Machine clients have no user or groups, so they are authorized by custom scope.
    if "orders/read" not in scopes(claims):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing scope")
    return {"orders": [1, 2, 3]}
