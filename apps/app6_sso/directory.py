"""The app's own copy of its users, kept current by logins and by SCIM."""

import json
import uuid

from redis.asyncio import Redis


class Directory:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def get(self, user_id: str) -> dict | None:
        raw = await self.redis.get(f"dir:user:{user_id}")
        return json.loads(raw) if raw else None

    async def find_by_username(self, username: str) -> dict | None:
        user_id = await self.redis.get(f"dir:name:{username.lower()}")
        return await self.get(user_id) if user_id else None

    async def create(self, username: str, name: str, source: str, external_id: str = "") -> dict:
        user = {
            "id": str(uuid.uuid4()),
            "username": username.lower(),
            "name": name,
            "active": True,
            "source": source,
            "external_id": external_id,
        }
        if not await self.redis.set(f"dir:name:{user['username']}", user["id"], nx=True):
            raise ValueError("Username already exists")
        await self.save(user)
        return user

    async def save(self, user: dict) -> None:
        await self.redis.set(f"dir:user:{user['id']}", json.dumps(user))

    async def delete(self, user: dict) -> None:
        await self.redis.delete(f"dir:user:{user['id']}", f"dir:name:{user['username']}")

    async def provision_on_login(self, username: str, name: str) -> dict:
        """Just-in-time provisioning: create at first login, and refresh details after that."""
        user = await self.find_by_username(username)
        if user is None:
            return await self.create(username, name, source="jit")
        if user["name"] != name:
            user["name"] = name
            await self.save(user)
        return user

    async def remember_session(self, username: str, session_id: str, idp_sid: str) -> None:
        await self.redis.sadd(f"dir:sessions:{username.lower()}", session_id)
        if idp_sid:
            await self.redis.sadd(f"dir:sid:{idp_sid}", session_id)

    async def sessions_for_user(self, username: str) -> set[str]:
        return await self.redis.smembers(f"dir:sessions:{username.lower()}")

    async def sessions_for_idp_sid(self, idp_sid: str) -> set[str]:
        return await self.redis.smembers(f"dir:sid:{idp_sid}")

    async def first_use(self, token_id: str, ttl_seconds: int = 600) -> bool:
        return bool(await self.redis.set(f"dir:seen:{token_id}", "1", nx=True, ex=ttl_seconds))
