"""Exercise 2: server-side sessions stored in Redis.

Run:  uv run uvicorn apps.phase1_fundamentals.exercise2_sessions:app --port 8102
"""

import json
import secrets
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from pwdlib import PasswordHash
from pydantic_settings import BaseSettings, SettingsConfigDict
from redis.asyncio import Redis


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHASE1_")

    redis_url: str = "redis://127.0.0.1:6380/0"
    # Browsers refuse Secure cookies over plain HTTP sites, so local labs turn it off.
    cookie_secure: bool = False
    session_ttl_seconds: int = 1800


settings = Settings()
app = FastAPI(title="Phase 1, Exercise 2: Sessions")
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
password_hash = PasswordHash.recommended()

COOKIE_NAME = "session_id"
USERS = {"asha": password_hash.hash("correct-horse-battery")}
DUMMY_HASH = password_hash.hash("not-a-real-account")


def get_redis() -> Redis:
    return redis_client


RedisDep = Annotated[Redis, Depends(get_redis)]
SessionCookie = Annotated[str | None, Cookie(alias=COOKIE_NAME)]


def session_key(session_id: str) -> str:
    return f"session:{session_id}"


async def current_session(redis: RedisDep, session_id: SessionCookie = None) -> dict[str, str]:
    raw = await redis.get(session_key(session_id)) if session_id else None
    if raw is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    # Sliding expiry: an active user stays signed in, and an idle session ends on its own.
    await redis.expire(session_key(session_id), settings.session_ttl_seconds)
    return json.loads(raw)


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return """
    <h1>Session demo</h1>
    <form method="post" action="/login">
      <input name="username" placeholder="username">
      <input name="password" type="password" placeholder="password">
      <button>Sign in</button>
    </form>
    """


@app.post("/login")
async def login(
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    response: Response,
    request: Request,
    redis: RedisDep,
) -> dict[str, str]:
    stored_hash = USERS.get(username, DUMMY_HASH)
    if not password_hash.verify(password, stored_hash) or username not in USERS:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    # Drop any session the browser already held, which blocks session fixation.
    old_session_id = request.cookies.get(COOKIE_NAME)
    if old_session_id:
        await redis.delete(session_key(old_session_id))

    # A long random ID cannot be guessed, and it means nothing without the Redis record.
    session_id = secrets.token_urlsafe(32)
    await redis.set(
        session_key(session_id),
        json.dumps({"username": username}),
        ex=settings.session_ttl_seconds,
    )
    response.set_cookie(
        COOKIE_NAME,
        session_id,
        httponly=True,  # JavaScript cannot read it, so XSS cannot simply copy it.
        samesite="lax",  # Not sent on cross-site POST requests.
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_seconds,
    )
    return {"message": f"Signed in as {username}"}


@app.get("/me")
async def me(session: Annotated[dict[str, str], Depends(current_session)]) -> dict[str, str]:
    return session


@app.post("/logout")
async def logout(
    response: Response,
    redis: RedisDep,
    session_id: SessionCookie = None,
) -> dict[str, str]:
    # Deleting the server record ends the session at once, even if the cookie was copied.
    if session_id:
        await redis.delete(session_key(session_id))
    response.delete_cookie(COOKIE_NAME)
    return {"message": "Signed out"}
