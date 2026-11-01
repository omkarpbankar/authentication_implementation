"""Deciding when two logins are the same person. This is the hard part of third-party login."""

import json
import secrets
import time
import uuid

from redis.asyncio import Redis

from apps.app5_social.providers import Profile

ATTEMPT_TTL_SECONDS = 300


class AccountExists(Exception):
    """A verified email matches an account that this login is not linked to."""


class IdentityTaken(Exception):
    """This provider login is already linked to a different account."""


class LastLoginMethod(Exception):
    pass


class Accounts:
    def __init__(self, redis: Redis, session_ttl: int) -> None:
        self.redis = redis
        self.session_ttl = session_ttl

    async def owner_of(self, provider: str, subject: str) -> str | None:
        return await self.redis.get(f"identity:{provider}:{subject}")

    async def _claim_identity(self, user_id: str, profile: Profile) -> bool:
        key = f"identity:{profile.provider}:{profile.subject}"
        # NX means two parallel logins cannot link one identity to two accounts.
        if not await self.redis.set(key, user_id, nx=True):
            return await self.redis.get(key) == user_id
        await self.redis.hset(
            f"user:{user_id}:identities",
            profile.provider,
            json.dumps({"subject": profile.subject, "email": profile.email}),
        )
        return True

    async def sign_in(self, profile: Profile) -> str:
        existing = await self.owner_of(profile.provider, profile.subject)
        if existing:
            return existing

        if profile.email and profile.email_verified:
            if await self.redis.exists(f"email:{profile.email}"):
                # Never merge on a matching email. Linking must be a deliberate action,
                # taken by someone who has proved they own the existing account.
                raise AccountExists(profile.email)

        user_id = str(uuid.uuid4())
        await self.redis.hset(
            f"user:{user_id}",
            mapping={
                "name": profile.name,
                "email": profile.email if profile.email_verified else "",
            },
        )
        await self._claim_identity(user_id, profile)
        # Only a verified email can claim an address. This stops account pre-hijacking, where
        # someone registers a victim's email first and waits for the victim to arrive.
        if profile.email and profile.email_verified:
            await self.redis.set(f"email:{profile.email}", user_id, nx=True)
        return user_id

    async def link(self, user_id: str, profile: Profile) -> None:
        if not await self._claim_identity(user_id, profile):
            raise IdentityTaken(profile.provider)

    async def identities(self, user_id: str) -> dict[str, dict]:
        raw = await self.redis.hgetall(f"user:{user_id}:identities")
        return {provider: json.loads(value) for provider, value in raw.items()}

    async def unlink(self, user_id: str, provider: str) -> None:
        identities = await self.identities(user_id)
        if provider not in identities:
            return
        if len(identities) == 1:
            # Removing this would leave the account with no way to sign in.
            raise LastLoginMethod
        await self.redis.delete(f"identity:{provider}:{identities[provider]['subject']}")
        await self.redis.hdel(f"user:{user_id}:identities", provider)

    async def user(self, user_id: str) -> dict:
        return await self.redis.hgetall(f"user:{user_id}")

    async def save_attempt(self, state: str, attempt: dict) -> None:
        await self.redis.set(f"attempt:{state}", json.dumps(attempt), ex=ATTEMPT_TTL_SECONDS)

    async def take_attempt(self, state: str) -> dict | None:
        raw = await self.redis.getdel(f"attempt:{state}")
        return json.loads(raw) if raw else None

    async def create_session(self, user_id: str) -> str:
        session_id = secrets.token_urlsafe(32)
        session = {
            "user_id": user_id,
            "authenticated_at": int(time.time()),
            "csrf_token": secrets.token_urlsafe(32),
        }
        await self.redis.set(f"session:{session_id}", json.dumps(session), ex=self.session_ttl)
        return session_id

    async def session(self, session_id: str | None) -> dict | None:
        raw = await self.redis.get(f"session:{session_id}") if session_id else None
        return json.loads(raw) if raw else None

    async def end_session(self, session_id: str) -> None:
        await self.redis.delete(f"session:{session_id}")

    async def save_provider_token(self, user_id: str, provider: str, encrypted: str) -> None:
        await self.redis.hset(f"user:{user_id}:tokens", provider, encrypted)

    async def provider_token(self, user_id: str, provider: str) -> str | None:
        return await self.redis.hget(f"user:{user_id}:tokens", provider)
