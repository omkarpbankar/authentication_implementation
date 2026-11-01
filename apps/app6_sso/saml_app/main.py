"""App 6: a SAML Service Provider, using python3-saml.

Runs in a Linux container, because its xmlsec dependency is unreliable on Windows.
Run:  docker compose --profile saml up -d --build saml-app
"""

import os
import re
import secrets
import time
import urllib.request
from typing import Annotated

from fastapi import Cookie, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
from onelogin.saml2.settings import OneLogin_Saml2_Settings

BASE_URL = "http://localhost:8007"
SESSION_COOKIE = "saml_session"
PENDING_COOKIE = "saml_pending"
IDP_REALM = "http://localhost:8080/realms/course"
PERSISTENT_NAME_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


def build_settings(idp_cert: str, idp_entity_id: str = IDP_REALM) -> dict:
    return {
        # Strict mode turns on the audience, destination, and time window checks.
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{BASE_URL}/saml/metadata",
            "assertionConsumerService": {"url": f"{BASE_URL}/saml/acs", "binding": HTTP_POST},
            "singleLogoutService": {"url": f"{BASE_URL}/saml/sls", "binding": HTTP_REDIRECT},
            "NameIDFormat": PERSISTENT_NAME_ID,
        },
        "idp": {
            "entityId": idp_entity_id,
            "singleSignOnService": {"url": f"{IDP_REALM}/protocol/saml", "binding": HTTP_REDIRECT},
            "singleLogoutService": {"url": f"{IDP_REALM}/protocol/saml", "binding": HTTP_REDIRECT},
            "x509cert": idp_cert,
        },
        "security": {
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "rejectDeprecatedAlgorithm": True,
            "rejectUnsolicitedResponsesWithInResponseTo": True,
            "requestedAuthnContext": False,
        },
    }


def fetch_idp_certificate() -> str:
    """Download the IdP's signing certificate over the private Docker network."""
    url = os.environ["IDP_DESCRIPTOR_URL"]
    for _ in range(30):
        try:
            # The URL comes from deployment settings, not from a user.
            with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310  # nosec B310
                return re.search(
                    r"<(?:\w+:)?X509Certificate>([^<]+)<", response.read().decode()
                ).group(1)
        except OSError:
            time.sleep(2)
    raise RuntimeError("Could not read the IdP certificate")


def safe_relay_state(value: str) -> str:
    # RelayState comes back through the browser, so it could be an attacker's URL.
    if value.startswith("/") and not value.startswith(("//", "/\\")):
        return value
    return "/profile"


def create_app(saml_settings: dict) -> FastAPI:
    app = FastAPI(title="App 6: SAML Service Provider")
    app.state.sessions = {}
    app.state.pending_requests = {}
    app.state.seen_assertions = {}

    def saml_request(request: Request, form: dict | None = None) -> dict:
        # Built from fixed configuration, because the Host header is attacker-controlled.
        return {
            "https": "off",
            "http_host": "localhost:8007",
            "script_name": request.url.path,
            "get_data": dict(request.query_params),
            "post_data": form or {},
        }

    def session_for(session_id: str | None) -> dict:
        session = app.state.sessions.get(session_id or "")
        if session is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
        return session

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return '<h1>App 6 SAML</h1><a href="/saml/login">Sign in</a>'

    @app.get("/saml/metadata")
    def metadata() -> Response:
        settings = OneLogin_Saml2_Settings(saml_settings, sp_validation_only=True)
        document = settings.get_sp_metadata()
        errors = settings.validate_metadata(document)
        if errors:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Invalid metadata")
        return Response(document, media_type="application/xml")

    @app.get("/saml/login")
    def login(request: Request, next: str = "/profile") -> RedirectResponse:  # noqa: A002
        auth = OneLogin_Saml2_Auth(saml_request(request), saml_settings)
        url = auth.login(return_to=safe_relay_state(next))
        # Remember which request we sent, so only a reply to it is accepted.
        pending_id = secrets.token_urlsafe(32)
        app.state.pending_requests[pending_id] = auth.get_last_request_id()
        response = RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(PENDING_COOKIE, pending_id, httponly=True, max_age=300)
        return response

    @app.post("/saml/acs")
    async def assertion_consumer(
        request: Request,
        pending_id: Annotated[str | None, Cookie(alias=PENDING_COOKIE)] = None,
    ) -> RedirectResponse:
        request_id = app.state.pending_requests.pop(pending_id or "", None)
        if request_id is None:
            # IdP-initiated login is refused, as we cannot tie it to anything we asked for.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Unsolicited SAML response")

        form = dict(await request.form())
        auth = OneLogin_Saml2_Auth(saml_request(request, form), saml_settings)
        try:
            auth.process_response(request_id=request_id)
        except OneLogin_Saml2_ValidationError as exc:
            # A malformed assertion is a refusal, never a server error.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "SAML response rejected") from exc
        if auth.get_errors() or not auth.is_authenticated():
            raise HTTPException(status.HTTP_403_FORBIDDEN, "SAML response rejected")

        assertion_id = auth.get_last_assertion_id()
        if assertion_id in app.state.seen_assertions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Assertion already used")
        app.state.seen_assertions[assertion_id] = auth.get_last_assertion_not_on_or_after()

        attributes = auth.get_attributes()
        session_id = secrets.token_urlsafe(32)
        app.state.sessions[session_id] = {
            "name_id": auth.get_nameid(),
            "session_index": auth.get_session_index(),
            "email": (attributes.get("email") or [""])[0],
            "roles": attributes.get("roles", []),
        }
        target = safe_relay_state(form.get("RelayState", "/profile"))
        response = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
        response.delete_cookie(PENDING_COOKIE)
        return response

    @app.get("/profile")
    def profile(session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None) -> dict:
        return session_for(session_id)

    @app.get("/saml/logout")
    def logout(
        request: Request,
        session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    ) -> RedirectResponse:
        session = session_for(session_id)
        auth = OneLogin_Saml2_Auth(saml_request(request), saml_settings)
        url = auth.logout(
            return_to="/", name_id=session["name_id"], session_index=session["session_index"]
        )
        app.state.sessions.pop(session_id, None)
        return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/saml/sls")
    def single_logout(
        request: Request,
        session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    ) -> RedirectResponse:
        auth = OneLogin_Saml2_Auth(saml_request(request), saml_settings)
        url = auth.process_slo(delete_session_cb=lambda: app.state.sessions.pop(session_id, None))
        response = RedirectResponse(url or "/", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE)
        return response

    return app


def production_app() -> FastAPI:
    return create_app(build_settings(fetch_idp_certificate()))
