"""Server-side storage. Tokens stay here, and the browser only ever holds a random ID."""

import json
import secrets

from redis.asyncio import Redis

LOGIN_ATTEMPT_TTL_SECONDS = 300


class SessionStore:
    def __init__(self, redis: Redis, ttl_seconds: int) -> None:
        self.redis = redis
        self.ttl = ttl_seconds

    async def save_login_attempt(
        self, state: str, verifier: str, nonce: str, next_path: str
    ) -> None:
        record = json.dumps({"verifier": verifier, "nonce": nonce, "next": next_path})
        await self.redis.set(f"login:{state}", record, ex=LOGIN_ATTEMPT_TTL_SECONDS)

    async def take_login_attempt(self, state: str) -> dict | None:
        # GETDEL makes each attempt single-use, so a captured callback cannot be replayed.
        raw = await self.redis.getdel(f"login:{state}")
        return json.loads(raw) if raw else None

    async def create(self, data: dict) -> str:
        session_id = secrets.token_urlsafe(32)
        await self.redis.set(f"session:{session_id}", json.dumps(data), ex=self.ttl)
        return session_id

    async def get(self, session_id: str | None) -> dict | None:
        if not session_id:
            return None
        raw = await self.redis.get(f"session:{session_id}")
        return json.loads(raw) if raw else None

    async def update(self, session_id: str, data: dict) -> None:
        await self.redis.set(f"session:{session_id}", json.dumps(data), ex=self.ttl)

    async def delete(self, session_id: str) -> None:
        await self.redis.delete(f"session:{session_id}")
