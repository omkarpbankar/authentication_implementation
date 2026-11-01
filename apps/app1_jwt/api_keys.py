"""API keys for scripts and partners.

Format: ak_<prefix>_<secret>. The prefix finds the record and is safe to show. Only a hash of
the secret is stored, so a stolen database contains no usable keys.
"""

import hashlib
import secrets
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from apps.app1_jwt.deps import ClaimsDep, StoreDep

router = APIRouter(tags=["API keys"])
ALLOWED_SCOPES = {"reports:read", "reports:write"}


class NewKey(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    scopes: list[str]
    expires_in_days: int = Field(default=90, ge=1, le=365)


def hash_secret(secret: str) -> str:
    # SHA-256 is fine here, because the input is long and random, unlike a human password.
    return hashlib.sha256(secret.encode()).hexdigest()


def public_view(record: dict) -> dict:
    return {key: value for key, value in record.items() if key != "secret_hash"}


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_key(body: NewKey, claims: ClaimsDep, store: StoreDep) -> dict:
    if not set(body.scopes) <= ALLOWED_SCOPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown scope")
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    record = {
        "prefix": prefix,
        "name": body.name,
        "user_id": claims.user_id,
        "scopes": body.scopes,
        "secret_hash": hash_secret(secret),
        "expires_at": int(time.time()) + body.expires_in_days * 86400,
        "last_used_at": None,
    }
    await store.save_api_key(prefix, record)
    # Shown once. If it is lost, the owner creates a new one.
    return {**public_view(record), "key": f"ak_{prefix}_{secret}"}


@router.get("/api-keys")
async def list_keys(claims: ClaimsDep, store: StoreDep) -> list[dict]:
    return [public_view(record) for record in await store.list_api_keys(claims.user_id)]


@router.delete("/api-keys/{prefix}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(prefix: str, claims: ClaimsDep, store: StoreDep) -> None:
    record = await store.get_api_key(prefix)
    # Someone else's key looks the same as a missing one.
    if record is None or record["user_id"] != claims.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found")
    await store.delete_api_key(claims.user_id, prefix)


async def api_key_record(
    store: StoreDep, x_api_key: Annotated[str | None, Header()] = None
) -> dict:
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    try:
        _, prefix, secret = (x_api_key or "").split("_", 2)
    except ValueError as exc:
        raise invalid from exc

    record = await store.get_api_key(prefix)
    if record is None or not secrets.compare_digest(record["secret_hash"], hash_secret(secret)):
        raise invalid
    if record["expires_at"] <= time.time():
        raise invalid
    record["last_used_at"] = int(time.time())
    await store.save_api_key(prefix, record)
    return record


def require_key_scope(scope: str):
    def check(record: Annotated[dict, Depends(api_key_record)]) -> dict:
        if scope not in record["scopes"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This key lacks that scope")
        return record

    return check


@router.get("/partner/reports")
def partner_reports(record: Annotated[dict, Depends(require_key_scope("reports:read"))]) -> dict:
    return {"reports": ["Q1", "Q2"], "key_name": record["name"]}
