"""Files. Tiers set the storage limit, Standard adds folders, and Premium adds share links.

Run:  uv run uvicorn apps.app8_access.files_app.main:app --port 8014
"""

import hashlib
import hmac
import secrets
import time
from html import escape
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, status
from fastapi.responses import HTMLResponse, Response

from apps.app8_access.access_client.client import User
from apps.app8_access.access_client.guard import AppConfig, Guard, page
from apps.app8_access.catalog import FILES_ID

app = FastAPI(title="Files")
config = AppConfig("files", "Files", FILES_ID, "files-app", 8014)
guard = Guard(app, config)

Access = tuple[User, dict]
LINK_TTL_SECONDS = 300
LINK_SECRET = secrets.token_bytes(32)


def usage_key(user: User) -> str:
    return f"files:{user.tenant}:{user.subject}:mb"


def sign_link(user: User, name: str, expires: int) -> str:
    message = f"{user.subject}|{name}|{expires}".encode()
    return hmac.new(LINK_SECRET, message, hashlib.sha256).hexdigest()


@app.get("/", response_class=HTMLResponse)
async def home(
    access: Annotated[Access, Depends(guard.require_feature("files.storage_mb"))],
) -> Response:
    user, context = access
    used = int(await guard.redis.get(usage_key(user)) or 0)
    limit = context["features"]["files.storage_mb"]
    return page(
        "Files",
        f"""
        <p>{escape(user.email)}, plan: <b>{escape(context["tier"].title())}</b></p>
        <p>Storage: {used} of {limit} MB</p>
        <form method="post" action="/upload">
          <input name="size_mb" type="number" value="10"><button>Upload</button>
        </form>
        <form method="post" action="/logout"><button>Sign out</button></form>
        """,
    )


@app.post("/upload")
async def upload(
    user: Annotated[User, Depends(guard.current_user)],
    size_mb: Annotated[int, Form(ge=1, le=10_000)],
) -> dict:
    used = int(await guard.redis.get(usage_key(user)) or 0)
    # The check includes this upload, so a large file cannot jump over the limit.
    await guard.access.check(user, "files.storage_mb", usage=used + size_mb - 1)
    await guard.redis.incrby(usage_key(user), size_mb)
    return {"used_mb": used + size_mb}


@app.post("/folders")
async def create_folder(
    access: Annotated[Access, Depends(guard.require_feature("files.folders"))],
) -> dict:
    return {"created": True}


@app.post("/share-links")
async def create_share_link(
    access: Annotated[Access, Depends(guard.require_feature("files.share_links"))],
    name: Annotated[str, Form(max_length=200)],
) -> dict:
    user, _ = access
    expires = int(time.time()) + LINK_TTL_SECONDS
    return {"url": f"/shared/{name}?expires={expires}&sig={sign_link(user, name, expires)}"}


@app.get("/shared/{name}")
async def open_share_link(
    name: str,
    expires: int,
    sig: str,
    access: Annotated[Access, Depends(guard.require_feature("files.share_links"))],
) -> dict:
    user, _ = access
    expected = sign_link(user, name, expires)
    # Links are short-lived, and the owner's access is checked again when one is used.
    if expires < time.time() or not secrets.compare_digest(sig, expected):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This link has expired")
    return {"file": name}
