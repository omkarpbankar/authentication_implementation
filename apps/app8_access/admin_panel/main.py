"""The admin panel. It holds no rules of its own, and calls the Access Service for everything.

Run:  uv run uvicorn apps.app8_access.admin_panel.main:app --port 8011
"""

import secrets
import time
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode, urlsplit
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from redis.asyncio import Redis

from apps.app2_oidc.oidc import OidcProvider, TokenError, new_pkce_pair
from apps.app2_oidc.sessions import SessionStore
from apps.app8_access.access_service.settings import settings
from apps.shared.hardening import apply_hardening

CLIENT_ID = "admin-panel"
CLIENT_SECRET = "admin-panel-dev-secret"  # noqa: S105  A public practice value.
SESSION_COOKIE = "admin_session"
STATE_COOKIE = "admin_login_state"
SCOPE = "openid profile email organization"
IDLE_LIMIT_SECONDS = 900
TOTAL_LIMIT_SECONDS = 28_800
REFRESH_MARGIN_SECONDS = 15
TIERS = ["basic", "standard", "premium"]


def login_origin(issuer: str) -> str:
    parts = urlsplit(issuer)
    return f"{parts.scheme}://{parts.netloc}"


app = FastAPI(title="Admin Panel")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
default_provider = OidcProvider(settings.issuer)
http_client = httpx.AsyncClient(timeout=10)


def get_provider() -> OidcProvider:
    return default_provider


def get_store() -> SessionStore:
    return SessionStore(redis_client, TOTAL_LIMIT_SECONDS)


def get_http() -> httpx.AsyncClient:
    return http_client


ProviderDep = Annotated[OidcProvider, Depends(get_provider)]
StoreDep = Annotated[SessionStore, Depends(get_store)]
HttpDep = Annotated[httpx.AsyncClient, Depends(get_http)]


class NeedsLogin(Exception):
    def __init__(self, target: str, force: bool = False) -> None:
        super().__init__(target)
        self.target = target
        self.force = force


class ApiFailure(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# No page here runs any script, so the browser can refuse all of it. Forms may reach the login
# server too, because signing out redirects there, and browsers apply this rule to redirects.
apply_hardening(
    app,
    csp=(
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; "
        f"form-action 'self' {login_origin(settings.issuer)}"
    ),
)


@app.exception_handler(NeedsLogin)
async def to_login(request: Request, exc: NeedsLogin) -> Response:
    query = urlencode({"next": exc.target, **({"force": "1"} if exc.force else {})})
    return RedirectResponse(f"/login?{query}", status_code=status.HTTP_303_SEE_OTHER)


@app.exception_handler(ApiFailure)
async def show_failure(request: Request, exc: ApiFailure) -> Response:
    return message_page(request, "That did not work", exc.detail, exc.status_code)


def message_page(
    request: Request, title: str, message: str, status_code: int = 200
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "message.html",
        {"title": title, "message": message, "session": None},
        status_code=status_code,
    )


def safe_next(path: str) -> str:
    if path.startswith("/") and not path.startswith(("//", "/\\")):
        return path
    return "/"


@app.get("/login")
async def login(
    store: StoreDep,
    provider: ProviderDep,
    next: str = "/",
    force: str = "",  # noqa: A002
) -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce_pair()
    await store.save_login_attempt(state, verifier, nonce, safe_next(next))
    url = await provider.authorization_url(
        CLIENT_ID, f"{settings.panel_url}/callback", state, nonce, challenge, SCOPE
    )
    # A sensitive action can ask the admin to prove they are still at the keyboard.
    if force:
        url += "&prompt=login&max_age=0"
    response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(STATE_COOKIE, state, httponly=True, samesite="lax", max_age=300)
    return response


@app.get("/callback")
async def callback(
    request: Request,
    store: StoreDep,
    provider: ProviderDep,
    http: HttpDep,
    code: str = "",
    state: str = "",
) -> Response:
    cookie = request.cookies.get(STATE_COOKIE, "")
    if not state or not cookie or not secrets.compare_digest(state, cookie):
        return message_page(request, "Sign-in failed", "Please try again.", 400)
    attempt = await store.take_login_attempt(state)
    if attempt is None:
        return message_page(request, "Sign-in expired", "Please try again.", 400)
    try:
        tokens = await provider.exchange_code(
            code, attempt["verifier"], CLIENT_ID, CLIENT_SECRET, f"{settings.panel_url}/callback"
        )
        claims = await provider.validate_id_token(tokens["id_token"], CLIENT_ID, attempt["nonce"])
    except TokenError:
        return message_page(request, "Sign-in failed", "Please try again.", 400)

    if "otp" not in (claims.get("amr") or []):
        return message_page(
            request,
            "Multi-factor sign-in required",
            "Set up an authenticator app in your account, then sign in again.",
            403,
        )

    who = await http.get(
        f"{settings.access_service_url}/admin/v1/whoami",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    if who.status_code != 200:
        return message_page(request, "Not an admin", "Your account has no admin role.", 403)

    now = int(time.time())
    session_id = await store.create(
        {
            "email": claims.get("email", ""),
            "role": who.json()["role"],
            "actions": who.json()["actions"],
            "user_id": who.json()["user_id"],
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "id_token": tokens["id_token"],
            "expires_at": now + int(tokens.get("expires_in", 60)),
            "csrf_token": secrets.token_urlsafe(32),
            "signed_in_at": now,
            "last_seen_at": now,
        }
    )
    response = RedirectResponse(attempt["next"], status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict")
    response.delete_cookie(STATE_COOKIE)
    return response


async def current_session(request: Request, store: StoreDep, provider: ProviderDep) -> dict:
    session_id = request.cookies.get(SESSION_COOKIE)
    session = await store.get(session_id)
    target = request.url.path
    if session is None:
        raise NeedsLogin(target)

    now = time.time()
    idle = now - session["last_seen_at"] > IDLE_LIMIT_SECONDS
    too_long = now - session["signed_in_at"] > TOTAL_LIMIT_SECONDS
    if idle or too_long:
        await store.delete(session_id)
        raise NeedsLogin(target)

    if session["expires_at"] - REFRESH_MARGIN_SECONDS < now:
        try:
            tokens = await provider.refresh(session["refresh_token"], CLIENT_ID, CLIENT_SECRET)
        except TokenError as exc:
            await store.delete(session_id)
            raise NeedsLogin(target) from exc
        session["access_token"] = tokens["access_token"]
        session["refresh_token"] = tokens.get("refresh_token", session["refresh_token"])
        session["expires_at"] = int(now) + int(tokens.get("expires_in", 60))

    session["last_seen_at"] = int(now)
    await store.update(session_id, session)
    session["id"] = session_id
    return session


SessionDep = Annotated[dict, Depends(current_session)]
Reason = Annotated[str, Form(min_length=3, max_length=500)]


async def check_csrf(session: SessionDep, csrf_token: Annotated[str, Form()] = "") -> dict:
    if not secrets.compare_digest(csrf_token, session["csrf_token"]):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")
    return session


WriteSession = Annotated[dict, Depends(check_csrf)]


async def api(
    http: httpx.AsyncClient, session: dict, method: str, path: str, target: str = "/", **kwargs
):
    response = await http.request(
        method,
        f"{settings.access_service_url}/admin/v1{path}",
        headers={"Authorization": f"Bearer {session['access_token']}", **kwargs.pop("headers", {})},
        **kwargs,
    )
    if response.status_code < 300:
        return response.json() if "json" in response.headers.get("content-type", "") else None
    detail = "Something went wrong."
    if "json" in response.headers.get("content-type", ""):
        detail = str(response.json().get("detail", detail))
    if detail == "REAUTH_REQUIRED":
        raise NeedsLogin(target, force=True)
    raise ApiFailure(response.status_code, detail)


def render(request: Request, session: dict, template: str, **context) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        template,
        {
            "session": session,
            "tiers": TIERS,
            "idempotency_key": secrets.token_urlsafe(16),
            **context,
        },
    )


def done(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: SessionDep, http: HttpDep) -> Response:
    data = await api(http, session, "GET", "/dashboard")
    return render(request, session, "dashboard.html", data=data)


@app.get("/users", response_class=HTMLResponse)
async def users(
    request: Request,
    session: SessionDep,
    http: HttpDep,
    q: str = "",
    app_key: str = "",
    tier: str = "",
) -> Response:
    rows = await api(
        http, session, "GET", "/users", params={"q": q, "app_key": app_key, "tier": tier}
    )
    return render(request, session, "users.html", rows=rows, q=q, app_key=app_key, tier=tier)


@app.get("/users/{user_id}", response_class=HTMLResponse)
async def user_detail(
    user_id: UUID, request: Request, session: SessionDep, http: HttpDep
) -> Response:
    data = await api(http, session, "GET", f"/users/{user_id}")
    return render(request, session, "user_detail.html", data=data)


@app.post("/users/{user_id}/grant")
async def save_grant(
    user_id: UUID,
    session: WriteSession,
    http: HttpDep,
    application_id: Annotated[UUID, Form()],
    tier: Annotated[str, Form()],
    reason: Reason,
    idempotency_key: Annotated[str, Form()],
    expires_at: Annotated[str, Form()] = "",
    expected_version: Annotated[str, Form()] = "",
) -> Response:
    await api(
        http,
        session,
        "PUT",
        f"/users/{user_id}/grants/{application_id}",
        json={
            "tier": tier,
            "reason": reason,
            "expires_at": expires_at or None,
            "expected_version": int(expected_version) if expected_version else None,
        },
        headers={"Idempotency-Key": idempotency_key},
    )
    return done(f"/users/{user_id}")


@app.post("/users/{user_id}/grant-action")
async def grant_action(
    user_id: UUID,
    session: WriteSession,
    http: HttpDep,
    application_id: Annotated[UUID, Form()],
    action: Annotated[str, Form(pattern="^(suspend|resume|revoke)$")],
    reason: Reason,
) -> Response:
    await api(
        http,
        session,
        "POST",
        f"/users/{user_id}/grants/{application_id}/{action}",
        json={"reason": reason},
    )
    return done(f"/users/{user_id}")


@app.post("/users/{user_id}/disable")
async def disable_user(
    user_id: UUID, session: WriteSession, http: HttpDep, reason: Reason
) -> Response:
    await api(http, session, "POST", f"/users/{user_id}/disable", json={"reason": reason})
    return done(f"/users/{user_id}")


@app.get("/matrix", response_class=HTMLResponse)
async def matrix(request: Request, session: SessionDep, http: HttpDep) -> Response:
    data = await api(http, session, "GET", "/matrix")
    return render(request, session, "matrix.html", data=data)


@app.get("/applications", response_class=HTMLResponse)
async def applications(request: Request, session: SessionDep, http: HttpDep) -> Response:
    rows = await api(http, session, "GET", "/applications")
    return render(request, session, "applications.html", rows=rows)


@app.post("/applications/{application_id}/status")
async def application_status(
    application_id: UUID,
    session: WriteSession,
    http: HttpDep,
    new_status: Annotated[str, Form()],
    reason: Reason,
) -> Response:
    await api(
        http,
        session,
        "PUT",
        f"/applications/{application_id}/status",
        json={"status": new_status, "reason": reason},
    )
    return done("/applications")


@app.get("/groups", response_class=HTMLResponse)
async def groups(request: Request, session: SessionDep, http: HttpDep) -> Response:
    rows = await api(http, session, "GET", "/groups")
    applications_list = await api(http, session, "GET", "/applications")
    people = await api(http, session, "GET", "/users")
    return render(
        request, session, "groups.html", rows=rows, applications=applications_list, people=people
    )


@app.post("/groups")
async def create_group(
    session: WriteSession, http: HttpDep, name: Annotated[str, Form(max_length=80)]
) -> Response:
    await api(http, session, "POST", "/groups", json={"name": name})
    return done("/groups")


@app.post("/groups/{group_id}/members")
async def add_member(
    group_id: UUID, session: WriteSession, http: HttpDep, user_id: Annotated[UUID, Form()]
) -> Response:
    await api(http, session, "PUT", f"/groups/{group_id}/members/{user_id}")
    return done("/groups")


@app.post("/groups/{group_id}/members/{user_id}/remove")
async def remove_member(
    group_id: UUID, user_id: UUID, session: WriteSession, http: HttpDep
) -> Response:
    await api(http, session, "DELETE", f"/groups/{group_id}/members/{user_id}")
    return done("/groups")


@app.post("/groups/{group_id}/grant")
async def group_grant(
    group_id: UUID,
    session: WriteSession,
    http: HttpDep,
    application_id: Annotated[UUID, Form()],
    tier: Annotated[str, Form()],
    reason: Reason,
) -> Response:
    await api(
        http,
        session,
        "PUT",
        f"/groups/{group_id}/grant",
        json={"application_id": str(application_id), "tier": tier, "reason": reason},
    )
    return done("/groups")


@app.get("/requests", response_class=HTMLResponse)
async def requests_queue(request: Request, session: SessionDep, http: HttpDep) -> Response:
    rows = await api(http, session, "GET", "/requests")
    return render(request, session, "requests.html", rows=rows)


@app.post("/requests/{request_id}/approve")
async def approve(
    request_id: UUID,
    session: WriteSession,
    http: HttpDep,
    tier: Annotated[str, Form()],
    reason: Reason,
) -> Response:
    await api(
        http,
        session,
        "POST",
        f"/requests/{request_id}/approve",
        json={"tier": tier, "reason": reason},
    )
    return done("/requests")


@app.post("/requests/{request_id}/reject")
async def reject(
    request_id: UUID, session: WriteSession, http: HttpDep, reason: Reason
) -> Response:
    await api(http, session, "POST", f"/requests/{request_id}/reject", json={"reason": reason})
    return done("/requests")


@app.get("/bulk", response_class=HTMLResponse)
async def bulk_page(request: Request, session: SessionDep) -> Response:
    return render(request, session, "bulk.html", csv_text="", preview=None)


@app.post("/bulk/preview", response_class=HTMLResponse)
async def bulk_preview(
    request: Request,
    session: WriteSession,
    http: HttpDep,
    csv_text: Annotated[str, Form(max_length=200_000)],
) -> Response:
    preview = await api(http, session, "POST", "/bulk/preview", json={"csv": csv_text})
    return render(request, session, "bulk.html", csv_text=csv_text, preview=preview)


@app.post("/bulk/apply")
async def bulk_apply(
    session: WriteSession,
    http: HttpDep,
    csv_text: Annotated[str, Form(max_length=200_000)],
    reason: Reason,
) -> Response:
    await api(
        http,
        session,
        "POST",
        "/bulk/apply",
        target="/bulk",
        json={"csv": csv_text, "reason": reason},
    )
    return done("/")


@app.get("/reviews", response_class=HTMLResponse)
async def reviews(request: Request, session: SessionDep, http: HttpDep) -> Response:
    rows = await api(http, session, "GET", "/reviews")
    return render(request, session, "reviews.html", rows=rows)


@app.post("/reviews/{grant_id}/confirm")
async def confirm_review(grant_id: UUID, session: WriteSession, http: HttpDep) -> Response:
    await api(http, session, "POST", f"/reviews/{grant_id}/confirm")
    return done("/reviews")


@app.get("/audit", response_class=HTMLResponse)
async def audit(
    request: Request, session: SessionDep, http: HttpDep, reference: str = ""
) -> Response:
    rows = await api(http, session, "GET", "/audit", params={"reference": reference})
    return render(request, session, "audit.html", rows=rows, reference=reference)


@app.get("/admins", response_class=HTMLResponse)
async def admins(request: Request, session: SessionDep, http: HttpDep) -> Response:
    rows = await api(http, session, "GET", "/admins")
    applications_list = await api(http, session, "GET", "/applications")
    people = await api(http, session, "GET", "/users")
    return render(
        request, session, "admins.html", rows=rows, applications=applications_list, people=people
    )


@app.post("/admins")
async def assign_admin(
    session: WriteSession,
    http: HttpDep,
    user_id: Annotated[UUID, Form()],
    role: Annotated[str, Form()],
    reason: Reason,
    application_id: Annotated[str, Form()] = "",
) -> Response:
    await api(
        http,
        session,
        "PUT",
        f"/admins/{user_id}",
        target="/admins",
        json={"role": role, "reason": reason, "application_id": application_id or None},
    )
    return done("/admins")


@app.post("/admins/{user_id}/remove")
async def remove_admin(
    user_id: UUID, session: WriteSession, http: HttpDep, reason: Reason
) -> Response:
    await api(
        http,
        session,
        "DELETE",
        f"/admins/{user_id}",
        target="/admins",
        json={"reason": reason},
    )
    return done("/admins")


@app.post("/logout")
async def logout(session: WriteSession, store: StoreDep, provider: ProviderDep) -> RedirectResponse:
    await store.delete(session["id"])
    metadata = await provider.metadata()
    query = urlencode(
        {
            "id_token_hint": session["id_token"],
            "post_logout_redirect_uri": f"{settings.panel_url}/",
        }
    )
    response = done(f"{metadata['end_session_endpoint']}?{query}")
    response.delete_cookie(SESSION_COOKIE)
    return response
