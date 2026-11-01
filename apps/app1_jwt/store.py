"""All App 1 state lives in Redis, which keeps the lesson focused on tokens."""

import json
import secrets
import time
import uuid

from redis.asyncio import Redis

from apps.app1_jwt.tokens import hash_refresh_token


class Store:
    def __init__(self, redis: Redis, refresh_ttl_seconds: int) -> None:
        self.redis = redis
        self.refresh_ttl = refresh_ttl_seconds

    async def create_user(self, email: str, password_hash: str) -> bool:
        record = {"id": str(uuid.uuid4()), "email": email, "password_hash": password_hash}
        # NX makes this atomic, so two sign-ups for one email cannot both succeed.
        created = await self.redis.set(f"user:email:{email}", json.dumps(record), nx=True)
        if created:
            await self.redis.set(f"user:id:{record['id']}", email)
        return bool(created)

    async def get_user_by_email(self, email: str) -> dict | None:
        raw = await self.redis.get(f"user:email:{email}")
        return json.loads(raw) if raw else None

    async def get_user_by_id(self, user_id: str) -> dict | None:
        email = await self.redis.get(f"user:id:{user_id}")
        return await self.get_user_by_email(email) if email else None

    async def save_user(self, user: dict) -> None:
        await self.redis.set(f"user:email:{user['email']}", json.dumps(user))

    async def save_refresh_token(self, token: str, user_id: str, family_id: str) -> None:
        record = json.dumps({"user_id": user_id, "family_id": family_id})
        await self.redis.set(f"refresh:{hash_refresh_token(token)}", record, ex=self.refresh_ttl)
        await self.redis.sadd(f"user_families:{user_id}", family_id)
        await self.redis.set(
            f"family_started:{family_id}", str(int(time.time())), nx=True, ex=self.refresh_ttl
        )

    async def get_refresh_token(self, token: str) -> dict | None:
        raw = await self.redis.get(f"refresh:{hash_refresh_token(token)}")
        return json.loads(raw) if raw else None

    async def claim_refresh_token(self, token: str) -> bool:
        """True the first time only. Atomic, so two parallel refreshes cannot both win."""
        key = f"refresh_used:{hash_refresh_token(token)}"
        return bool(await self.redis.set(key, "1", nx=True, ex=self.refresh_ttl))

    async def revoke_family(self, family_id: str) -> None:
        await self.redis.set(f"family_revoked:{family_id}", "1", ex=self.refresh_ttl)

    async def is_family_revoked(self, family_id: str) -> bool:
        return bool(await self.redis.exists(f"family_revoked:{family_id}"))

    async def deny_access_token(self, jti: str, expires_at: int) -> None:
        # Kept only until the token expires, so the denylist stays small.
        ttl = max(int(expires_at - time.time()), 1)
        await self.redis.set(f"denied:{jti}", "1", ex=ttl)

    async def is_access_token_denied(self, jti: str) -> bool:
        return bool(await self.redis.exists(f"denied:{jti}"))

    async def active_sessions(self, user_id: str) -> list[dict]:
        sessions = []
        for family_id in await self.redis.smembers(f"user_families:{user_id}"):
            started = await self.redis.get(f"family_started:{family_id}")
            if started and not await self.is_family_revoked(family_id):
                sessions.append({"id": family_id, "started_at": int(started)})
        return sorted(sessions, key=lambda session: session["started_at"])

    async def revoke_session(self, user_id: str, family_id: str) -> bool:
        if not await self.redis.sismember(f"user_families:{user_id}", family_id):
            return False
        await self.revoke_family(family_id)
        return True

    async def revoke_everything(self, user_id: str) -> None:
        """Used after a password change, which may mean someone else was signed in."""
        for family_id in await self.redis.smembers(f"user_families:{user_id}"):
            await self.revoke_family(family_id)
        # Access tokens issued before this moment stop working too.
        await self.redis.set(f"not_before:{user_id}", str(int(time.time())))

    async def tokens_valid_after(self, user_id: str) -> int:
        return int(await self.redis.get(f"not_before:{user_id}") or 0)

    async def set_mfa(self, user_id: str, record: dict) -> None:
        await self.redis.set(f"mfa:{user_id}", json.dumps(record))

    async def get_mfa(self, user_id: str) -> dict | None:
        raw = await self.redis.get(f"mfa:{user_id}")
        return json.loads(raw) if raw else None

    async def new_mfa_ticket(self, user_id: str) -> str:
        ticket = secrets.token_urlsafe(32)
        record = json.dumps({"user_id": user_id, "attempts": 0})
        await self.redis.set(f"mfa_ticket:{ticket}", record, ex=300)
        return ticket

    async def read_mfa_ticket(self, ticket: str) -> dict | None:
        raw = await self.redis.get(f"mfa_ticket:{ticket}")
        return json.loads(raw) if raw else None

    async def count_mfa_attempt(self, ticket: str, record: dict) -> None:
        record["attempts"] += 1
        await self.redis.set(f"mfa_ticket:{ticket}", json.dumps(record), keepttl=True)

    async def end_mfa_ticket(self, ticket: str) -> None:
        await self.redis.delete(f"mfa_ticket:{ticket}")

    async def claim_totp_step(self, user_id: str, step: int) -> bool:
        """A code works once, so one seen over someone's shoulder cannot be reused."""
        return bool(await self.redis.set(f"totp_used:{user_id}:{step}", "1", nx=True, ex=120))

    async def mark_recent_mfa(self, user_id: str) -> None:
        await self.redis.set(f"mfa_recent:{user_id}", "1", ex=300)

    async def has_recent_mfa(self, user_id: str) -> bool:
        return bool(await self.redis.exists(f"mfa_recent:{user_id}"))

    async def save_single_use(self, kind: str, token: str, value: str, ttl: int) -> None:
        await self.redis.set(f"{kind}:{hash_refresh_token(token)}", value, ex=ttl)

    async def take_single_use(self, kind: str, token: str) -> str | None:
        # GETDEL is atomic, so two requests cannot both spend one token.
        return await self.redis.getdel(f"{kind}:{hash_refresh_token(token)}")

    async def save_passkey(self, user_id: str, credential_id: str, record: dict) -> None:
        await self.redis.set(f"passkey:{credential_id}", json.dumps({**record, "user_id": user_id}))

    async def get_passkey(self, credential_id: str) -> dict | None:
        raw = await self.redis.get(f"passkey:{credential_id}")
        return json.loads(raw) if raw else None

    async def save_api_key(self, prefix: str, record: dict) -> None:
        await self.redis.set(f"apikey:{prefix}", json.dumps(record))
        await self.redis.sadd(f"apikeys:{record['user_id']}", prefix)

    async def get_api_key(self, prefix: str) -> dict | None:
        raw = await self.redis.get(f"apikey:{prefix}")
        return json.loads(raw) if raw else None

    async def list_api_keys(self, user_id: str) -> list[dict]:
        prefixes = await self.redis.smembers(f"apikeys:{user_id}")
        keys = [await self.get_api_key(prefix) for prefix in sorted(prefixes)]
        return [key for key in keys if key]

    async def delete_api_key(self, user_id: str, prefix: str) -> None:
        await self.redis.delete(f"apikey:{prefix}")
        await self.redis.srem(f"apikeys:{user_id}", prefix)
