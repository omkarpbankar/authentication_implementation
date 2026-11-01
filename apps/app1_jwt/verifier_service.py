"""A separate service that trusts App 1's tokens using only its public JWKS URL.

It holds no secret, so it can check tokens but can never create one.
Run:  uv run uvicorn apps.app1_jwt.verifier_service:app --port 8011
"""

from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic_settings import BaseSettings, SettingsConfigDict


class VerifierSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VERIFIER_")

    jwks_url: str = "http://localhost:8001/.well-known/jwks.json"
    issuer: str = "http://localhost:8001"
    audience: str = "app1-api"


settings = VerifierSettings()
app = FastAPI(title="App 1: separate verifier service")
bearer = HTTPBearer(auto_error=False)
jwks_client = jwt.PyJWKClient(settings.jwks_url, cache_keys=True, lifespan=300)


def get_jwks_client() -> jwt.PyJWKClient:
    return jwks_client


# A plain def on purpose. PyJWKClient blocks during network calls, and FastAPI runs plain
# def dependencies in a thread pool, so the server's event loop is never held up.
def verified_payload(
    client: Annotated[jwt.PyJWKClient, Depends(get_jwks_client)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        signing_key = client.get_signing_key_from_jwt(credentials.credentials)
        payload = jwt.decode(
            credentials.credentials,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.audience,
            issuer=settings.issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc
    if payload.get("typ") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return payload


@app.get("/whoami")
def whoami(payload: Annotated[dict, Depends(verified_payload)]) -> dict[str, str]:
    return {"user_id": payload["sub"], "verified_by": "public key only"}
