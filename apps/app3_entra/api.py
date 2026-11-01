"""A protected API for Entra ID tokens, with scopes, app roles, and On-Behalf-Of.

Run:  uv run uvicorn apps.app3_entra.api:app --port 8013
"""

import asyncio
from typing import Annotated

import httpx
import msal
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apps.app2_oidc.oidc import TokenError
from apps.app3_entra.settings import settings
from apps.app3_entra.tokens import EntraTokenValidator, app_roles, is_app_only, scopes

app = FastAPI(title="App 3: Entra ID protected API")
bearer = HTTPBearer(auto_error=False)
default_validator = EntraTokenValidator(
    settings.login_host,
    settings.allowed_tenants,
    [settings.api_client_id, f"api://{settings.api_client_id}"],
)


def get_validator() -> EntraTokenValidator:
    return default_validator


def get_obo_client() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        settings.api_client_id,
        authority=settings.authority,
        client_credential=settings.api_client_secret,
    )


Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


async def access_claims(
    validator: Annotated[EntraTokenValidator, Depends(get_validator)], credentials: Credentials
) -> dict:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        return await validator.validate(credentials.credentials)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc


ClaimsDep = Annotated[dict, Depends(access_claims)]


def require_scope(scope: str):
    def check(claims: ClaimsDep) -> dict:
        if scope not in scopes(claims):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing scope")
        return claims

    return check


def require_role(*allowed: str):
    def check(claims: ClaimsDep) -> dict:
        if not app_roles(claims) & set(allowed):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing role")
        return claims

    return check


@app.get("/api/me")
def me(claims: Annotated[dict, Depends(require_scope("access_as_user"))]) -> dict:
    return {"tenant": claims["tid"], "object_id": claims.get("oid"), "name": claims.get("name")}


@app.get("/api/reports")
def read_reports(claims: Annotated[dict, Depends(require_role("Reader", "Writer"))]) -> dict:
    return {"reports": ["Q1", "Q2"], "app_only": is_app_only(claims)}


@app.post("/api/reports")
def create_report(claims: Annotated[dict, Depends(require_role("Writer"))]) -> dict:
    return {"created": True}


@app.get("/api/graph-me")
async def graph_me(
    claims: Annotated[dict, Depends(require_scope("access_as_user"))],
    credentials: Credentials,
    client: Annotated[msal.ConfidentialClientApplication, Depends(get_obo_client)],
) -> dict:
    # On-Behalf-Of: swap the user's token for one that Graph accepts. This API never tries
    # to read or validate the Graph token, because that token is not meant for it.
    result = await asyncio.to_thread(
        client.acquire_token_on_behalf_of,
        user_assertion=credentials.credentials,
        scopes=["https://graph.microsoft.com/User.Read"],
    )
    if "access_token" not in result:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Could not reach Microsoft Graph")

    async with httpx.AsyncClient(timeout=10) as http:
        response = await http.get(
            settings.graph_url, headers={"Authorization": f"Bearer {result['access_token']}"}
        )
    if response.status_code != 200:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Microsoft Graph refused the request")
    profile = response.json()
    return {"display_name": profile.get("displayName"), "mail": profile.get("mail")}
