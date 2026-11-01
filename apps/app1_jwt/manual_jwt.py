"""A JWT built by hand with only the standard library, to show there is no magic.

This is for learning. Real code uses PyJWT, as in tokens.py.
Run:  uv run python -m apps.app1_jwt.manual_jwt
"""

import base64
import hashlib
import hmac
import json
import time

MIN_SECRET_BYTES = 32


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(signing_input: str, secret: bytes) -> str:
    return b64url_encode(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest())


def check_secret(secret: bytes) -> None:
    # A short secret can be cracked offline from any single token.
    if len(secret) < MIN_SECRET_BYTES:
        raise ValueError(f"HS256 secrets need at least {MIN_SECRET_BYTES} bytes")


def create_token(payload: dict, secret: bytes) -> str:
    check_secret(secret)
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header}.{body}"
    return f"{signing_input}.{sign(signing_input, secret)}"


def verify_token(token: str, secret: bytes) -> dict:
    check_secret(secret)
    try:
        header_b64, body_b64, signature = token.split(".")
    except ValueError as exc:
        raise ValueError("Token must have three parts") from exc

    # Never trust the token's own "alg". This code accepts one algorithm, chosen here.
    if json.loads(b64url_decode(header_b64)).get("alg") != "HS256":
        raise ValueError("Unexpected algorithm")

    expected = sign(f"{header_b64}.{body_b64}", secret)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Bad signature")

    payload = json.loads(b64url_decode(body_b64))
    if payload.get("exp", 0) <= time.time():
        raise ValueError("Token expired")
    return payload


if __name__ == "__main__":
    demo_secret = b"a-demo-secret-that-is-at-least-32-bytes-long"
    token = create_token({"sub": "asha", "exp": int(time.time()) + 60}, demo_secret)
    print("Token:   ", token)
    print("Payload: ", b64url_decode(token.split(".")[1]).decode(), "(readable without any key)")
    print("Verified:", verify_token(token, demo_secret))
