"""A small SCIM 2.0 endpoint, so a company's directory can manage users in this app.

Just-in-time provisioning only runs when someone logs in, so it can never remove anyone.
SCIM lets the directory deactivate a leaver straight away.
"""

import re
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apps.app6_sso.directory import Directory
from apps.app6_sso.settings import settings

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

router = APIRouter(prefix="/scim/v2")
bearer = HTTPBearer(auto_error=False)


def get_directory() -> Directory:
    raise NotImplementedError("Set by the app")


def get_end_sessions():
    raise NotImplementedError("Set by the app")


DirectoryDep = Annotated[Directory, Depends(get_directory)]
EndSessionsDep = Annotated[object, Depends(get_end_sessions)]


def require_scim_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> None:
    if credentials is None or not secrets.compare_digest(
        credentials.credentials, settings.scim_token
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid SCIM token")


Authorized = Depends(require_scim_token)


def scim_error(code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        {"schemas": [ERROR_SCHEMA], "status": str(code), "detail": detail}, status_code=code
    )


def to_scim(user: dict) -> dict:
    return {
        "schemas": [USER_SCHEMA],
        "id": user["id"],
        "externalId": user["external_id"],
        "userName": user["username"],
        "displayName": user["name"],
        "active": user["active"],
        "meta": {"resourceType": "User"},
    }


def display_name(body: dict) -> str:
    return body.get("displayName") or body.get("name", {}).get("formatted", "")


async def set_active(user: dict, active: bool, directory: Directory, end_sessions) -> None:
    user["active"] = active
    await directory.save(user)
    if not active:
        # Deactivation must take effect now, not when their session happens to expire.
        await end_sessions(user["username"])


@router.post("/Users", dependencies=[Authorized], status_code=status.HTTP_201_CREATED)
async def create_user(request: Request, directory: DirectoryDep):
    body = await request.json()
    if not body.get("userName"):
        return scim_error(status.HTTP_400_BAD_REQUEST, "userName is required")
    try:
        user = await directory.create(
            body["userName"],
            display_name(body),
            source="scim",
            external_id=body.get("externalId", ""),
        )
    except ValueError:
        return scim_error(status.HTTP_409_CONFLICT, "User already exists")
    return to_scim(user)


@router.get("/Users", dependencies=[Authorized])
async def list_users(directory: DirectoryDep, filter: str = "") -> dict:  # noqa: A002
    match = re.fullmatch(r'userName eq "([^"]+)"', filter)
    user = await directory.find_by_username(match.group(1)) if match else None
    resources = [to_scim(user)] if user else []
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/Users/{user_id}", dependencies=[Authorized])
async def get_user(user_id: str, directory: DirectoryDep):
    user = await directory.get(user_id)
    return to_scim(user) if user else scim_error(status.HTTP_404_NOT_FOUND, "User not found")


@router.put("/Users/{user_id}", dependencies=[Authorized])
async def replace_user(
    user_id: str, request: Request, directory: DirectoryDep, end_sessions: EndSessionsDep
):
    user = await directory.get(user_id)
    if user is None:
        return scim_error(status.HTTP_404_NOT_FOUND, "User not found")
    body = await request.json()
    user["name"] = display_name(body)
    await set_active(user, bool(body.get("active", True)), directory, end_sessions)
    return to_scim(user)


@router.patch("/Users/{user_id}", dependencies=[Authorized])
async def patch_user(
    user_id: str, request: Request, directory: DirectoryDep, end_sessions: EndSessionsDep
):
    user = await directory.get(user_id)
    if user is None:
        return scim_error(status.HTTP_404_NOT_FOUND, "User not found")
    body = await request.json()
    if PATCH_SCHEMA not in body.get("schemas", []):
        return scim_error(status.HTTP_400_BAD_REQUEST, "Expected a PatchOp request")

    for operation in body.get("Operations", []):
        value = operation.get("value")
        # Providers send this in two shapes, so both are accepted.
        changes = value if isinstance(value, dict) else {operation.get("path"): value}
        if "active" in changes:
            active = changes["active"]
            if isinstance(active, str):
                active = active.lower() == "true"
            await set_active(user, active, directory, end_sessions)
    return to_scim(user)


@router.delete("/Users/{user_id}", dependencies=[Authorized])
async def delete_user(user_id: str, directory: DirectoryDep, end_sessions: EndSessionsDep):
    user = await directory.get(user_id)
    if user is None:
        return scim_error(status.HTTP_404_NOT_FOUND, "User not found")
    await end_sessions(user["username"])
    await directory.delete(user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
