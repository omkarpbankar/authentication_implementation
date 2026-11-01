"""The attack lab. Every forged token here must be rejected."""

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.app1_jwt.settings import settings
from apps.app1_jwt.tokens import create_access_token

from .conftest import bearer


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def claims(**overrides):
    now = int(time.time())
    return {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": "asha",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": "attack",
        "fid": "family",
        "typ": "access",
        **overrides,
    }


def signed(ring, **overrides):
    headers = {"kid": ring.active_kid}
    return jwt.encode(claims(**overrides), ring.active_key, algorithm="RS256", headers=headers)


def assert_rejected(client, token):
    assert client.get("/users/me", headers=bearer(token)).status_code == 401


def test_control_a_correctly_signed_token_passes_verification(client, ring):
    # The user does not exist, so this is still a 401, which proves nothing alone.
    from apps.app1_jwt.tokens import verify_access_token

    claims_out = verify_access_token(signed(ring), ring, settings.issuer, settings.audience)
    assert claims_out.user_id == "asha"


def test_alg_none_is_rejected(client, ring):
    header = b64(json.dumps({"alg": "none", "typ": "JWT", "kid": ring.active_kid}).encode())
    body = b64(json.dumps(claims()).encode())
    assert_rejected(client, f"{header}.{body}.")


def test_rs256_to_hs256_confusion_is_rejected(client, ring):
    """The classic trick: sign with HS256, using the public key as the secret."""
    public_pem = ring.active_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": ring.active_kid}).encode())
    body = b64(json.dumps(claims()).encode())
    signature = hmac.new(public_pem, f"{header}.{body}".encode(), hashlib.sha256).digest()
    assert_rejected(client, f"{header}.{body}.{b64(signature)}")


def test_tampered_payload_is_rejected(client, ring):
    header, _, signature = signed(ring).split(".")
    forged_body = b64(json.dumps(claims(sub="admin")).encode())
    assert_rejected(client, f"{header}.{forged_body}.{signature}")


def test_token_signed_by_an_unknown_key_is_rejected(client, ring):
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims(), attacker_key, algorithm="RS256", headers={"kid": ring.active_kid})
    assert_rejected(client, token)


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(time.time()) - 10},
        {"aud": "another-api"},
        {"iss": "https://evil.example"},
        {"typ": "refresh"},
        {"nbf": int(time.time()) + 3600},
    ],
    ids=["expired", "wrong-audience", "wrong-issuer", "wrong-type", "not-yet-valid"],
)
def test_wrong_claims_are_rejected(client, ring, overrides):
    assert_rejected(client, signed(ring, **overrides))


def test_missing_expiry_is_rejected(client, ring):
    payload = claims()
    del payload["exp"]
    token = jwt.encode(
        payload, ring.active_key, algorithm="RS256", headers={"kid": ring.active_kid}
    )
    assert_rejected(client, token)


def test_opaque_refresh_token_is_not_an_access_token(client, tokens):
    assert_rejected(client, tokens["refresh_token"])


def test_missing_and_junk_tokens_are_rejected(client):
    assert client.get("/users/me").status_code == 401
    assert_rejected(client, "not-a-token")


def test_helper_builds_real_tokens(client, ring):
    token = create_access_token(ring, "asha", "f", settings.issuer, settings.audience, 60)
    assert len(token.split(".")) == 3
