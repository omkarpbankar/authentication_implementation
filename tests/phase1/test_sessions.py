import asyncio

import fakeredis.aioredis
import pytest
from fastapi.testclient import TestClient

from apps.phase1_fundamentals.exercise2_sessions import COOKIE_NAME, app, get_redis, session_key

LOGIN = {"username": "asha", "password": "correct-horse-battery"}


@pytest.fixture
def redis():
    return fakeredis.aioredis.FakeRedis(decode_responses=True)


@pytest.fixture
def client(redis):
    app.dependency_overrides[get_redis] = lambda: redis
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_me_requires_a_session(client):
    assert client.get("/me").status_code == 401


def test_login_then_me(client):
    assert client.post("/login", data=LOGIN).status_code == 200
    assert client.get("/me").json() == {"username": "asha"}


def test_wrong_password_and_unknown_user_look_identical(client):
    wrong_password = client.post("/login", data={**LOGIN, "password": "wrong"})
    unknown_user = client.post("/login", data={"username": "nobody", "password": "wrong"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_cookie_has_security_flags(client):
    set_cookie = client.post("/login", data=LOGIN).headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


def test_made_up_session_id_is_rejected(client):
    client.cookies.set(COOKIE_NAME, "made-up-value")
    assert client.get("/me").status_code == 401


def test_login_issues_a_new_session_id(client):
    """A session ID planted before login must stop working, which blocks session fixation."""
    client.post("/login", data=LOGIN)
    first_id = client.cookies[COOKIE_NAME]
    client.post("/login", data=LOGIN)
    second_id = client.cookies[COOKIE_NAME]

    assert first_id != second_id
    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, first_id)
    assert client.get("/me").status_code == 401


def test_logout_kills_the_session_even_for_a_copied_cookie(client):
    client.post("/login", data=LOGIN)
    stolen_cookie = client.cookies[COOKIE_NAME]

    client.post("/logout")

    client.cookies.clear()
    client.cookies.set(COOKIE_NAME, stolen_cookie)
    assert client.get("/me").status_code == 401


def test_deleting_the_server_record_revokes_access(client, redis):
    """This is the key difference from a JWT: the server can end a session at any moment."""
    client.post("/login", data=LOGIN)
    session_id = client.cookies[COOKIE_NAME]

    asyncio.run(redis.delete(session_key(session_id)))

    assert client.get("/me").status_code == 401
