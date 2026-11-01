"""Everything each protected app shares: sign-in, enforcement, and the denied pages.

The application ID comes from this app's own configuration, never from the browser.
"""

import secrets
from dataclasses import dataclass
from html import escape
from typing import Annotated
from urllib.parse import quote, urlencode
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis

from apps.app2_oidc.oidc import OidcProvider, TokenError, new_pkce_pair
from apps.app2_oidc.sessions import SessionStore
from apps.app8_access.access_client.client import (
    AccessClient,
    AccessDenied,
    AccessUnavailable,
    ServiceToken,
    User,
)
from apps.app8_access.access_client.messages import NOT_AUTHORIZED, REQUESTABLE, describe
from apps.app8_access.access_service.settings import settings
from apps.shared.hardening import apply_hardening

SCOPE = "openid profile email organization"
UNAVAILABLE_MESSAGE = "This application is temporarily unavailable. Please try again soon."


class NeedsLogin(Exception):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self.target = target


@dataclass
class AppConfig:
    app_key: str
    title: str
    application_id: UUID
    client_id: str
    port: int

    @property
    def client_secret(self) -> str:
        return f"{self.client_id}-dev-secret"

    @property
    def base_url(self) -> str:
        return f"http://localhost:{self.port}"

    @property
    def cookie(self) -> str:
        return f"{self.app_key}_session"


def safe_next(path: str) -> str:
    if path.startswith("/") and not path.startswith(("//", "/\\")):
        return path
    return "/"


def wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or "application/json" in request.headers.get(
        "accept", ""
    )


def page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
        <title>{escape(title)}</title>
        <style>body{{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}}
        </style></head><body><h1>{escape(title)}</h1>{body}</body></html>""",
        status_code=status_code,
    )


class Guard:
    """One per app. Holds the connections, and provides the dependencies its routes use."""

    def __init__(self, app: FastAPI, config: AppConfig) -> None:
        self.app = app
        self.config = config
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)
        self.provider = OidcProvider(settings.issuer)
        self.sessions = SessionStore(self.redis, 3600)
        http = httpx.AsyncClient(timeout=3)
        self.token = ServiceToken(
            f"{settings.issuer}/protocol/openid-connect/token",
            config.client_id,
            config.client_secret,
            http,
        )
        self.access = AccessClient(
            settings.access_service_url,
            config.application_id,
            self.token,
            self.redis,
            http,
            settings.cache_ttl_seconds,
        )
        self.bearer = HTTPBearer(auto_error=False)
        apply_hardening(app)
        self._add_routes()
        self._add_handlers()

    def _user_from(self, claims: dict) -> User:
        organizations = claims.get("organization") or []
        return User(
            subject=claims["sub"],
            tenant=organizations[0] if organizations else "",
            email=claims.get("email", ""),
            name=claims.get("name", claims.get("preferred_username", "")),
            issuer=claims.get("iss", ""),
        )

    async def session(self, request: Request) -> dict | None:
        return await self.sessions.get(request.cookies.get(self.config.cookie))

    async def current_user(self, request: Request) -> User:
        session = await self.session(request)
        if session is None:
            target = request.url.path
            if request.url.query:
                target += f"?{request.url.query}"
            raise NeedsLogin(target)
        return User(**session["user"])

    def require_app_access(self):
        async def check(user: Annotated[User, Depends(self.current_user)]) -> tuple[User, dict]:
            return user, await self.access.check(user)

        return check

    def require_feature(self, feature: str):
        async def check(user: Annotated[User, Depends(self.current_user)]) -> tuple[User, dict]:
            return user, await self.access.check(user, feature)

        return check

    def _add_handlers(self) -> None:
        config = self.config

        @self.app.exception_handler(NeedsLogin)
        async def to_login(request: Request, exc: NeedsLogin) -> Response:
            if wants_json(request):
                return problem(401, "NOT_AUTHENTICATED", "Please sign in.")
            return RedirectResponse(
                f"/login?next={quote(exc.target)}", status_code=status.HTTP_303_SEE_OTHER
            )

        @self.app.exception_handler(AccessDenied)
        async def denied(request: Request, exc: AccessDenied) -> Response:
            status_code, message = describe(exc.reason_code, exc.tier)
            if wants_json(request):
                return problem(status_code, exc.reason_code, message, exc.reference_id)

            session = await self.session(request)
            email = escape(session["user"]["email"]) if session else ""
            request_button = ""
            if exc.reason_code in REQUESTABLE:
                request_button = """
                <form method="post" action="/request-access">
                  <input name="note" placeholder="Why do you need access?" maxlength="500">
                  <button>Request access</button>
                </form>"""
            # This page must never redirect to login, or the user would loop forever.
            return page(
                config.title,
                f"""
                <p><b>{escape(message)}</b></p>
                <p>Signed in as {email}.</p>
                {request_button}
                <form method="post" action="/logout"><button>Sign out</button></form>
                <p><small>Reference: {escape(exc.reference_id)}</small></p>
                """,
                status_code,
            )

        @self.app.exception_handler(AccessUnavailable)
        async def unavailable(request: Request, exc: AccessUnavailable) -> Response:
            # Never the "not authorized" message, which would blame the user for an outage.
            if wants_json(request):
                return problem(503, "ACCESS_UNAVAILABLE", UNAVAILABLE_MESSAGE)
            return page(config.title, f"<p>{UNAVAILABLE_MESSAGE}</p>", 503)

    def _add_routes(self) -> None:
        app, config = self.app, self.config
        redirect_uri = f"{config.base_url}/callback"

        @app.get("/login")
        async def login(next: str = "/") -> Response:  # noqa: A002
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            verifier, challenge = new_pkce_pair()
            await self.sessions.save_login_attempt(state, verifier, nonce, safe_next(next))
            url = await self.provider.authorization_url(
                config.client_id, redirect_uri, state, nonce, challenge, SCOPE
            )
            response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                f"{config.app_key}_state", state, httponly=True, samesite="lax", max_age=300
            )
            return response

        @app.get("/callback")
        async def callback(request: Request, code: str = "", state: str = "") -> Response:
            cookie = request.cookies.get(f"{config.app_key}_state", "")
            if not state or not cookie or not secrets.compare_digest(state, cookie):
                return page(config.title, "<p>Sign-in failed. Please try again.</p>", 400)
            attempt = await self.sessions.take_login_attempt(state)
            if attempt is None:
                return page(config.title, "<p>Sign-in expired. Please try again.</p>", 400)
            try:
                tokens = await self.provider.exchange_code(
                    code, attempt["verifier"], config.client_id, config.client_secret, redirect_uri
                )
                claims = await self.provider.validate_id_token(
                    tokens["id_token"], config.client_id, attempt["nonce"]
                )
            except TokenError:
                return page(config.title, "<p>Sign-in failed. Please try again.</p>", 400)

            user = self._user_from(claims)
            session_id = await self.sessions.create(
                {"user": user.__dict__, "id_token": tokens["id_token"]}
            )
            response = RedirectResponse(attempt["next"], status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(config.cookie, session_id, httponly=True, samesite="lax")
            response.delete_cookie(f"{config.app_key}_state")
            return response

        @app.post("/logout")
        async def logout(request: Request) -> Response:
            session_id = request.cookies.get(config.cookie)
            session = await self.sessions.get(session_id)
            target = "/"
            if session:
                await self.sessions.delete(session_id)
                metadata = await self.provider.metadata()
                query = urlencode(
                    {
                        "id_token_hint": session["id_token"],
                        "post_logout_redirect_uri": f"{config.base_url}/",
                    }
                )
                # Ending the login server's session lets someone switch accounts.
                target = f"{metadata['end_session_endpoint']}?{query}"
            response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie(config.cookie)
            return response

        @app.post("/request-access")
        async def request_access(
            user: Annotated[User, Depends(self.current_user)],
            note: Annotated[str, Form(max_length=500)] = "",
        ) -> Response:
            message = await self.access.request_access(user, note)
            return page(config.title, f"<p>{escape(message)}</p>", 202)

        @app.get("/api/me")
        async def api_me(
            credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(self.bearer)],
        ) -> Response:
            """For API clients. A token issued for another app fails the audience check."""
            if credentials is None:
                return problem(401, "NOT_AUTHENTICATED", "Missing token.")
            try:
                claims = await self.provider.validate_access_token(
                    credentials.credentials, config.client_id
                )
            except TokenError:
                return problem(401, "WRONG_AUDIENCE", "This token is not for this application.")
            user = self._user_from(claims)
            context = await self.access.check(user)
            return JSONResponse({"subject": user.subject, "tier": context.get("tier", "")})


def problem(status_code: int, code: str, detail: str, reference: str = "") -> JSONResponse:
    """RFC 9457 Problem Details, so API clients get the same reasons as people do."""
    return JSONResponse(
        {
            "type": f"https://course.example/problems/{code.lower()}",
            "title": code,
            "status": status_code,
            "detail": detail,
            "reason_code": code,
            "reference_id": reference,
        },
        status_code=status_code,
        media_type="application/problem+json",
    )


__all__ = ["NOT_AUTHORIZED", "AppConfig", "Guard", "page"]
