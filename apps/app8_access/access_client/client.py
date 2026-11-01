"""How an app talks to the Access Service. Fails closed, and caches for a very short time."""

import json
import time
from dataclasses import asdict, dataclass
from uuid import UUID

import httpx
from redis.asyncio import Redis
from redis.exceptions import RedisError

REFRESH_MARGIN_SECONDS = 30


@dataclass(frozen=True)
class User:
    subject: str
    tenant: str
    email: str = ""
    name: str = ""
    issuer: str = ""


class AccessDenied(Exception):
    def __init__(self, reason_code: str, reference_id: str = "", tier: str = "") -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.reference_id = reference_id
        self.tier = tier


class AccessUnavailable(Exception):
    """The Access Service could not answer, so nothing can be granted."""


class ServiceToken:
    """The app's own identity, used to call the Access Service."""

    def __init__(self, token_url: str, client_id: str, client_secret: str, http) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = http
        self._token = ""
        self._expires_at = 0.0

    async def get(self) -> str:
        if time.time() < self._expires_at - REFRESH_MARGIN_SECONDS:
            return self._token
        response = await self.http.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        response.raise_for_status()
        body = response.json()
        self._token = body["access_token"]
        self._expires_at = time.time() + body.get("expires_in", 60)
        return self._token


class AccessClient:
    def __init__(
        self,
        base_url: str,
        application_id: UUID,
        token,
        redis: Redis,
        http: httpx.AsyncClient | None = None,
        cache_ttl: int = 30,
    ) -> None:
        self.base_url = base_url
        self.application_id = application_id
        self.token = token
        self.redis = redis
        self.http = http or httpx.AsyncClient(timeout=3)
        self.cache_ttl = cache_ttl

    async def _cache_key(self, user: User, feature: str) -> str | None:
        """The version numbers change on every grant change, which retires old entries."""
        try:
            versions = await self.redis.mget("ver:all", f"ver:user:{user.subject}")
        except RedisError:
            return None
        version = "-".join(value or "0" for value in versions)
        return f"decision:{self.application_id}:{user.subject}:{feature}:{version}"

    async def _cached(self, key: str | None) -> dict | None:
        if key is None:
            return None
        try:
            raw = await self.redis.get(key)
        except RedisError:
            return None
        return json.loads(raw) if raw else None

    async def _store(self, key: str | None, result: dict) -> None:
        if key is None:
            return
        try:
            await self.redis.set(key, json.dumps(result), ex=self.cache_ttl)
        except RedisError:
            return

    async def _ask(self, user: User, feature: str, usage: int | None) -> dict:
        body = {
            "subject": {"type": "user", "id": user.subject, "properties": asdict(user)},
            "resource": {"type": "application", "id": str(self.application_id)},
            "action": {"name": "use"},
            "context": {"tenant": user.tenant, "feature": feature, "usage": usage},
        }
        try:
            response = await self.http.post(
                f"{self.base_url}/access/v1/evaluation",
                json=body,
                headers={"Authorization": f"Bearer {await self.token.get()}"},
            )
        except httpx.HTTPError as exc:
            raise AccessUnavailable from exc
        if response.status_code != 200:
            raise AccessUnavailable
        return response.json()

    async def check(
        self, user: User, feature: str = "", usage: int | None = None, fresh: bool = False
    ) -> dict:
        """Returns the access details, or raises. Quota checks are never cached."""
        key = None
        if usage is None and not fresh:
            key = await self._cache_key(user, feature)
        result = await self._cached(key)
        if result is None:
            result = await self._ask(user, feature, usage)
            # Denials are cached too, so a refused user cannot flood the service.
            await self._store(key, result)

        context = result.get("context", {})
        if not result.get("decision"):
            raise AccessDenied(
                context.get("reason_code", "NO_APP_ACCESS"),
                context.get("reference_id", ""),
                context.get("tier", ""),
            )
        return context

    async def request_access(self, user: User, note: str = "") -> str:
        try:
            response = await self.http.post(
                f"{self.base_url}/access/v1/requests",
                json={
                    "subject": {"type": "user", "id": user.subject, "properties": asdict(user)},
                    "tenant": user.tenant,
                    "application_id": str(self.application_id),
                    "note": note,
                },
                headers={"Authorization": f"Bearer {await self.token.get()}"},
            )
        except httpx.HTTPError as exc:
            raise AccessUnavailable from exc
        if response.status_code == 429:
            return "You have sent several requests. Please wait for your admin."
        if response.status_code != 202:
            raise AccessUnavailable
        return response.json()["message"]
