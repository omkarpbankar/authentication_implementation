"""A protected API. It trusts tokens from Keycloak, and has no login of its own.

Run:  uv run uvicorn apps.app2_oidc.api:app --port 8022
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apps.app2_oidc.oidc import OidcProvider, TokenError
from apps.app2_oidc.settings import settings

app = FastAPI(title="App 2: protected API")
bearer = HTTPBearer(auto_error=False)
default_provider = OidcProvider(settings.issuer)


def get_provider() -> OidcProvider:
    return default_provider


async def access_claims(
    provider: Annotated[OidcProvider, Depends(get_provider)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        # The audience check is what makes this token "for us". An ID token fails it.
        return await provider.validate_access_token(credentials.credentials, settings.api_audience)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc


ClaimsDep = Annotated[dict, Depends(access_claims)]


def require_role(role: str):
    def check(claims: ClaimsDep) -> dict:
        if role not in claims.get("realm_access", {}).get("roles", []):
            # 403, not 401: we know who this is, and they may not do this.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing role")
        return claims

    return check


@app.get("/api/whoami")
def whoami(claims: ClaimsDep) -> dict:
    return {"subject": claims["sub"], "client": claims.get("azp", "")}


@app.post("/api/articles")
def create_article(claims: Annotated[dict, Depends(require_role("writer"))]) -> dict:
    return {"created_by": claims.get("preferred_username", claims["sub"])}
