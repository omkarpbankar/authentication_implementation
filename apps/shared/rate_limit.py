"""A small shared rate limiter, using a counter in Redis for each time window."""

import time

from fastapi import Request
from redis.asyncio import Redis
from redis.exceptions import RedisError


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = f"rate:{key}:{int(time.time()) // window_seconds}"
        try:
            count = await self.redis.incr(bucket)
            if count == 1:
                await self.redis.expire(bucket, window_seconds * 2)
        except (OSError, RedisError):
            # Open on purpose: a Redis outage must not stop every user from signing in.
            return True
        return count <= limit


def client_ip(request: Request) -> str:
    """Uvicorn replaces this with the real address only when the proxy is trusted.

    Reading X-Forwarded-For directly would let any client pick its own address, and so
    escape the limit. See forwarded-allow-ips in deploy/Dockerfile.
    """
    return request.client.host if request.client else "unknown"
