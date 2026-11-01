"""The shared enforcement client: caching, invalidation, and failing safely."""

from uuid import uuid4

import fakeredis.aioredis
import httpx
import pytest
import respx
from redis.exceptions import RedisError

from apps.app8_access.access_client.client import (
    AccessClient,
    AccessDenied,
    AccessUnavailable,
    ServiceToken,
    User,
)

BASE = "http://access.test"
URL = f"{BASE}/access/v1/evaluation"
USER = User(subject="user-1", tenant="acme", email="a@test.example")
ALLOWED = {"decision": True, "context": {"tier": "basic", "features": {}}}
DENIED = {"decision": False, "context": {"reason_code": "NO_APP_ACCESS", "reference_id": "ref1"}}


class FakeToken:
    async def get(self):
        return "service-token"


class BrokenRedis:
    def __getattr__(self, name):
        async def fail(*args, **kwargs):
            raise RedisError("down")

        return fail


@pytest.fixture
def redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def client(redis):
    return AccessClient(BASE, uuid4(), FakeToken(), redis, httpx.AsyncClient())


@respx.mock
async def test_allowed_decision_returns_the_details(client):
    respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    assert (await client.check(USER))["tier"] == "basic"


@respx.mock
async def test_denied_decision_raises_with_the_reason(client):
    respx.post(URL).mock(return_value=httpx.Response(200, json=DENIED))
    with pytest.raises(AccessDenied) as caught:
        await client.check(USER)
    assert caught.value.reason_code == "NO_APP_ACCESS"
    assert caught.value.reference_id == "ref1"


@respx.mock
async def test_second_check_uses_the_cache(client):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    await client.check(USER)
    await client.check(USER)
    assert route.call_count == 1


@respx.mock
async def test_denials_are_cached_too(client):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=DENIED))
    for _ in range(3):
        with pytest.raises(AccessDenied):
            await client.check(USER)
    assert route.call_count == 1


@respx.mock
async def test_changing_a_users_version_retires_the_cached_decision(client, redis):
    """This is how a revoked user is blocked straight away, with no wait for the cache."""
    route = respx.post(URL).mock(
        side_effect=[httpx.Response(200, json=ALLOWED), httpx.Response(200, json=DENIED)]
    )
    await client.check(USER)
    await redis.incr(f"ver:user:{USER.subject}")
    with pytest.raises(AccessDenied):
        await client.check(USER)
    assert route.call_count == 2


@respx.mock
async def test_global_version_also_retires_decisions(client, redis):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    await client.check(USER)
    await redis.incr("ver:all")
    await client.check(USER)
    assert route.call_count == 2


@respx.mock
async def test_cache_lifetime_is_short(client, redis):
    respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    await client.check(USER)
    key = (await redis.keys("decision:*"))[0]
    assert 0 < await redis.ttl(key) <= 30


@respx.mock
async def test_quota_checks_are_never_cached(client):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    await client.check(USER, "notes.create", usage=1)
    await client.check(USER, "notes.create", usage=2)
    assert route.call_count == 2


@respx.mock
async def test_fresh_checks_skip_the_cache(client):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    await client.check(USER)
    await client.check(USER, fresh=True)
    assert route.call_count == 2


@respx.mock
async def test_each_feature_has_its_own_cache_entry(client):
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    await client.check(USER, "notes.read")
    await client.check(USER, "notes.export")
    assert route.call_count == 2


@respx.mock
async def test_service_outage_fails_closed(client):
    respx.post(URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(AccessUnavailable):
        await client.check(USER)


@respx.mock
async def test_service_error_fails_closed(client):
    respx.post(URL).mock(return_value=httpx.Response(500))
    with pytest.raises(AccessUnavailable):
        await client.check(USER)


@respx.mock
async def test_timeout_fails_closed(client):
    respx.post(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(AccessUnavailable):
        await client.check(USER)


@respx.mock
async def test_redis_outage_falls_back_to_the_service():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json=ALLOWED))
    client = AccessClient(BASE, uuid4(), FakeToken(), BrokenRedis(), httpx.AsyncClient())
    assert (await client.check(USER))["tier"] == "basic"
    await client.check(USER)
    assert route.call_count == 2


@respx.mock
async def test_response_with_no_decision_is_a_denial(client):
    respx.post(URL).mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(AccessDenied):
        await client.check(USER)


@respx.mock
async def test_service_token_is_reused_until_it_expires():
    route = respx.post("http://idp.test/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t1", "expires_in": 300})
    )
    token = ServiceToken("http://idp.test/token", "app", "secret", httpx.AsyncClient())
    assert await token.get() == "t1"
    assert await token.get() == "t1"
    assert route.call_count == 1


@respx.mock
async def test_nearly_expired_service_token_is_replaced():
    route = respx.post("http://idp.test/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t1", "expires_in": 10})
    )
    token = ServiceToken("http://idp.test/token", "app", "secret", httpx.AsyncClient())
    await token.get()
    await token.get()
    assert route.call_count == 2
