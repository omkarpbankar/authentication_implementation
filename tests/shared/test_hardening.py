import json

import fakeredis.aioredis
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis.exceptions import RedisError

from apps.shared.hardening import REDACTED, apply_hardening, redact
from apps.shared.rate_limit import RateLimiter


def make_client(**options):
    app = FastAPI()
    apply_hardening(app, **options)

    @app.post("/echo")
    def echo():
        return {"ok": True}

    return TestClient(app)


def test_security_headers_are_on_every_response():
    headers = make_client().post("/echo").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert "default-src" in headers["content-security-policy"]
    assert headers["x-request-id"]


def test_hsts_is_only_sent_when_asked_for():
    assert "strict-transport-security" not in make_client().post("/echo").headers
    assert "strict-transport-security" in make_client(hsts=True).post("/echo").headers


def test_oversized_request_is_refused():
    response = make_client(max_body_bytes=10).post("/echo", content=b"x" * 100)
    assert response.status_code == 413


@pytest.mark.parametrize(
    "key",
    ["password", "access_token", "client_secret", "Authorization", "cookie", "api_key", "otp"],
)
def test_sensitive_fields_are_redacted(key):
    assert redact(None, None, {key: "value"})[key] == REDACTED


@pytest.mark.parametrize(
    "message",
    [
        "got eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln in header",
        "header was Bearer abc123",
        "used ak_1234abcd_secretvalue today",
    ],
)
def test_secrets_inside_messages_are_redacted(message):
    event = redact(None, None, {"event": message})
    assert "abc123" not in event["event"]
    assert "eyJzdWIi" not in event["event"]
    assert "secretvalue" not in event["event"]


def test_ordinary_fields_are_kept():
    event = redact(None, None, {"path": "/users", "status": 200})
    assert event == {"path": "/users", "status": 200}


def test_request_log_contains_no_query_string(capsys):
    client = make_client()
    client.post("/echo?token=super-secret-value")
    assert "super-secret-value" not in capsys.readouterr().out


def test_log_lines_are_json(capsys):
    make_client().post("/echo")
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert json.loads(line)["path"] == "/echo"


async def test_limiter_allows_up_to_the_limit():
    limiter = RateLimiter(fakeredis.aioredis.FakeRedis(decode_responses=True))
    results = [await limiter.allow("k", 3, 60) for _ in range(5)]
    assert results == [True, True, True, False, False]


async def test_limits_are_separate_per_key():
    limiter = RateLimiter(fakeredis.aioredis.FakeRedis(decode_responses=True))
    assert await limiter.allow("a", 1, 60)
    assert await limiter.allow("b", 1, 60)


async def test_redis_outage_does_not_stop_sign_ins():
    class Broken:
        async def incr(self, key):
            raise RedisError("down")

    assert await RateLimiter(Broken()).allow("k", 1, 60)
