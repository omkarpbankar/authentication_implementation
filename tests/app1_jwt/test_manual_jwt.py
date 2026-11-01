import time

import pytest

from apps.app1_jwt.manual_jwt import b64url_decode, create_token, verify_token

SECRET = b"a-test-secret-that-is-at-least-32-bytes-long"


def later():
    return int(time.time()) + 60


def test_round_trip():
    assert (
        verify_token(create_token({"sub": "asha", "exp": later()}, SECRET), SECRET)["sub"] == "asha"
    )


def test_payload_is_readable_without_the_secret():
    token = create_token({"sub": "asha", "exp": later()}, SECRET)
    assert b"asha" in b64url_decode(token.split(".")[1])


def test_wrong_secret_fails():
    token = create_token({"sub": "asha", "exp": later()}, SECRET)
    with pytest.raises(ValueError, match="Bad signature"):
        verify_token(token, b"another-secret-that-is-at-least-32-bytes")


def test_expired_token_fails():
    token = create_token({"sub": "asha", "exp": int(time.time()) - 1}, SECRET)
    with pytest.raises(ValueError, match="expired"):
        verify_token(token, SECRET)


def test_weak_secret_is_refused():
    with pytest.raises(ValueError, match="at least"):
        create_token({"sub": "asha"}, b"short")
