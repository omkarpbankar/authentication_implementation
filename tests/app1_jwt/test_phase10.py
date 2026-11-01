"""MFA, passkeys, magic links, password reset, and API keys."""

import base64
import hashlib
import json
import os
import re
import struct
import time

import cbor2
import pyotp
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from freezegun import freeze_time

from apps.app1_jwt import links, main

from .conftest import EMAIL, PASSWORD, bearer

RP_ID = "localhost"
ORIGIN = "http://localhost:8001"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftwareAuthenticator:
    """Behaves like a phone or security key: holds a private key, and signs challenges."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.count = 0

    def _cose_key(self):
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def register(self, options, origin=ORIGIN):
        client_data = json.dumps(
            {"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}
        ).encode()
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([0x45])
            + struct.pack(">I", self.count)
            + bytes(16)
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64(client_data), "attestationObject": b64(attestation)},
        }

    def sign_in(self, options, origin=ORIGIN, count=None, key=None):
        self.count = self.count + 1 if count is None else count
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}
        ).encode()
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        )
        signature = (key or self.key).sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data),
                "authenticatorData": b64(auth_data),
                "signature": b64(signature),
            },
        }


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append({"to": to, "subject": subject, "body": body})

    def latest_token(self):
        return re.search(r"token=(\S+)", self.sent[-1]["body"]).group(1)


@pytest.fixture
def mailer(client):
    fake = FakeMailer()
    main.app.dependency_overrides[links.get_mailer] = lambda: fake
    return fake


def enroll_mfa(client, tokens):
    headers = bearer(tokens["access_token"])
    secret = client.post("/mfa/totp/enroll", headers=headers).json()["secret"]
    response = client.post(
        "/mfa/totp/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=headers
    )
    return secret, response.json()["recovery_codes"]


def password_step(client):
    return client.post("/auth/login", data={"username": EMAIL, "password": PASSWORD}).json()


def code_at(secret, offset_steps=0):
    return pyotp.TOTP(secret).at(int(time.time()) + offset_steps * 30)


def test_login_without_mfa_is_unchanged(client, tokens):
    assert "access_token" in password_step(client)


def test_enrollment_needs_a_real_code(client, tokens):
    headers = bearer(tokens["access_token"])
    client.post("/mfa/totp/enroll", headers=headers)
    response = client.post("/mfa/totp/confirm", json={"code": "000000"}, headers=headers)
    assert response.status_code == 400


def test_enrollment_gives_a_qr_code(client, tokens):
    body = client.post("/mfa/totp/enroll", headers=bearer(tokens["access_token"])).json()
    assert body["uri"].startswith("otpauth://totp/")
    assert "<svg" in body["qr_svg"]


def test_password_alone_gives_no_tokens_once_mfa_is_on(client, tokens):
    enroll_mfa(client, tokens)
    step = password_step(client)
    assert step["mfa_required"] is True
    assert "access_token" not in step


def test_correct_code_finishes_login(client, tokens):
    secret, _ = enroll_mfa(client, tokens)
    ticket = password_step(client)["mfa_token"]
    response = client.post(
        "/auth/login/mfa", json={"mfa_token": ticket, "code": code_at(secret, 1)}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_wrong_code_is_rejected(client, tokens):
    enroll_mfa(client, tokens)
    ticket = password_step(client)["mfa_token"]
    response = client.post("/auth/login/mfa", json={"mfa_token": ticket, "code": "000000"})
    assert response.status_code == 401


def test_a_code_cannot_be_used_twice(client, tokens):
    secret, _ = enroll_mfa(client, tokens)
    code = code_at(secret, 1)
    first = password_step(client)["mfa_token"]
    assert (
        client.post("/auth/login/mfa", json={"mfa_token": first, "code": code}).status_code == 200
    )
    second = password_step(client)["mfa_token"]
    response = client.post("/auth/login/mfa", json={"mfa_token": second, "code": code})
    assert response.status_code == 401


def test_guessing_is_limited(client, tokens):
    enroll_mfa(client, tokens)
    ticket = password_step(client)["mfa_token"]
    for _ in range(5):
        client.post("/auth/login/mfa", json={"mfa_token": ticket, "code": "000000"})
    response = client.post("/auth/login/mfa", json={"mfa_token": ticket, "code": "000000"})
    assert response.status_code == 429


def test_recovery_code_works_once(client, tokens):
    _, codes = enroll_mfa(client, tokens)
    assert len(codes) == 10
    first = password_step(client)["mfa_token"]
    body = {"mfa_token": first, "recovery_code": codes[0]}
    assert client.post("/auth/login/mfa", json=body).status_code == 200
    second = password_step(client)["mfa_token"]
    body = {"mfa_token": second, "recovery_code": codes[0]}
    assert client.post("/auth/login/mfa", json=body).status_code == 401


def test_recovery_codes_and_totp_secret_are_not_stored_in_the_clear(client, tokens, redis):
    import asyncio

    secret, codes = enroll_mfa(client, tokens)
    stored = asyncio.run(_dump(redis))
    assert secret not in stored
    assert codes[0] not in stored


async def _dump(redis):
    out = ""
    for key in await redis.keys("mfa:*"):
        out += await redis.get(key)
    return out


def test_sensitive_action_needs_a_recent_code(client, tokens):
    secret, _ = enroll_mfa(client, tokens)
    headers = bearer(tokens["access_token"])
    assert client.post("/account/close-preview", headers=headers).status_code == 403
    client.post("/mfa/verify", json={"code": code_at(secret, -1)}, headers=headers)
    assert client.post("/account/close-preview", headers=headers).status_code == 200


def add_passkey(client, tokens, device):
    headers = bearer(tokens["access_token"])
    options = client.post("/passkeys/register/options", headers=headers).json()
    return client.post(
        "/passkeys/register/verify",
        json={"credential": device.register(options)},
        headers=headers,
    )


def passkey_login(client, device, **kwargs):
    start = client.post("/passkeys/login/options").json()
    return client.post(
        "/passkeys/login/verify",
        json={
            "challenge_id": start["challenge_id"],
            "credential": device.sign_in(start["options"], **kwargs),
        },
    )


def test_passkey_registers_and_signs_in(client, tokens):
    device = SoftwareAuthenticator()
    assert add_passkey(client, tokens, device).status_code == 201
    response = passkey_login(client, device)
    assert response.status_code == 200
    me = client.get("/users/me", headers=bearer(response.json()["access_token"]))
    assert me.json()["email"] == EMAIL


def test_passkey_is_refused_on_a_phishing_site(client, tokens):
    device = SoftwareAuthenticator()
    add_passkey(client, tokens, device)
    response = passkey_login(client, device, origin="http://evil-copy.example")
    assert response.status_code == 401


def test_passkey_signed_by_the_wrong_key_is_refused(client, tokens):
    device = SoftwareAuthenticator()
    add_passkey(client, tokens, device)
    other_key = ec.generate_private_key(ec.SECP256R1())
    assert passkey_login(client, device, key=other_key).status_code == 401


def test_passkey_response_cannot_be_replayed(client, tokens):
    device = SoftwareAuthenticator()
    add_passkey(client, tokens, device)
    start = client.post("/passkeys/login/options").json()
    body = {
        "challenge_id": start["challenge_id"],
        "credential": device.sign_in(start["options"]),
    }
    assert client.post("/passkeys/login/verify", json=body).status_code == 200
    assert client.post("/passkeys/login/verify", json=body).status_code == 401


def test_cloned_passkey_is_detected_by_its_counter(client, tokens):
    device = SoftwareAuthenticator()
    add_passkey(client, tokens, device)
    assert passkey_login(client, device, count=10).status_code == 200
    assert passkey_login(client, device, count=5).status_code == 401


def test_passkey_registration_from_another_origin_is_refused(client, tokens):
    device = SoftwareAuthenticator()
    headers = bearer(tokens["access_token"])
    options = client.post("/passkeys/register/options", headers=headers).json()
    response = client.post(
        "/passkeys/register/verify",
        json={"credential": device.register(options, origin="http://evil.example")},
        headers=headers,
    )
    assert response.status_code == 400


def test_magic_link_signs_in_once(client, tokens, mailer):
    client.post("/auth/magic/request", json={"email": EMAIL})
    token = mailer.latest_token()
    assert client.post("/auth/magic/verify", json={"token": token}).status_code == 200
    assert client.post("/auth/magic/verify", json={"token": token}).status_code == 401


def test_magic_link_expires(client, tokens, mailer, redis):
    import asyncio

    client.post("/auth/magic/request", json={"email": EMAIL})
    keys = asyncio.run(redis.keys("magic:*"))
    assert 0 < asyncio.run(redis.ttl(keys[0])) <= links.MAGIC_TTL_SECONDS


def test_requests_for_unknown_emails_look_identical_and_send_nothing(client, tokens, mailer):
    known = client.post("/auth/magic/request", json={"email": EMAIL})
    unknown = client.post("/auth/magic/request", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert len(mailer.sent) == 1


def test_stored_link_token_is_only_a_hash(client, tokens, mailer, redis):
    import asyncio

    client.post("/auth/magic/request", json={"email": EMAIL})
    keys = asyncio.run(redis.keys("magic:*"))
    assert mailer.latest_token() not in keys[0]


def test_password_reset_changes_the_password_and_ends_all_sessions(client, tokens, mailer):
    old_headers = bearer(tokens["access_token"])
    client.post("/auth/reset/request", json={"email": EMAIL})
    with freeze_time(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + 2))):
        response = client.post(
            "/auth/reset/confirm",
            json={"token": mailer.latest_token(), "new_password": "a-brand-new-password"},
        )
    assert response.status_code == 200

    assert client.get("/users/me", headers=old_headers).status_code == 401
    refresh = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401
    assert (
        client.post("/auth/login", data={"username": EMAIL, "password": PASSWORD}).status_code
        == 401
    )
    login = client.post("/auth/login", data={"username": EMAIL, "password": "a-brand-new-password"})
    assert login.status_code == 200


def test_reset_token_works_once(client, tokens, mailer):
    client.post("/auth/reset/request", json={"email": EMAIL})
    token = mailer.latest_token()
    body = {"token": token, "new_password": "a-brand-new-password"}
    assert client.post("/auth/reset/confirm", json=body).status_code == 200
    assert client.post("/auth/reset/confirm", json=body).status_code == 400


def test_magic_token_cannot_be_used_for_a_reset(client, tokens, mailer):
    client.post("/auth/magic/request", json={"email": EMAIL})
    body = {"token": mailer.latest_token(), "new_password": "a-brand-new-password"}
    assert client.post("/auth/reset/confirm", json=body).status_code == 400


def new_key(client, tokens, scopes=("reports:read",), **fields):
    return client.post(
        "/api-keys",
        json={"name": "Partner", "scopes": list(scopes), **fields},
        headers=bearer(tokens["access_token"]),
    ).json()


def test_api_key_works_and_records_use(client, tokens):
    created = new_key(client, tokens)
    response = client.get("/partner/reports", headers={"X-API-Key": created["key"]})
    assert response.status_code == 200
    listed = client.get("/api-keys", headers=bearer(tokens["access_token"])).json()
    assert listed[0]["last_used_at"] is not None


def test_full_key_is_shown_once_and_never_stored_or_listed(client, tokens, redis):
    import asyncio

    created = new_key(client, tokens)
    secret = created["key"].split("_", 2)[2]
    listed = client.get("/api-keys", headers=bearer(tokens["access_token"]))
    assert secret not in listed.text
    assert "secret_hash" not in listed.text
    assert secret not in asyncio.run(redis.get(f"apikey:{created['prefix']}"))


def test_wrong_key_secret_is_rejected(client, tokens):
    created = new_key(client, tokens)
    forged = f"ak_{created['prefix']}_not-the-secret"
    assert client.get("/partner/reports", headers={"X-API-Key": forged}).status_code == 401


def test_missing_or_malformed_keys_are_rejected(client):
    assert client.get("/partner/reports").status_code == 401
    assert client.get("/partner/reports", headers={"X-API-Key": "junk"}).status_code == 401


def test_key_scope_is_enforced(client, tokens):
    created = new_key(client, tokens, scopes=("reports:write",))
    response = client.get("/partner/reports", headers={"X-API-Key": created["key"]})
    assert response.status_code == 403


def test_unknown_scope_cannot_be_requested(client, tokens):
    response = client.post(
        "/api-keys",
        json={"name": "x", "scopes": ["admin"]},
        headers=bearer(tokens["access_token"]),
    )
    assert response.status_code == 422


def test_revoked_key_stops_at_once(client, tokens):
    created = new_key(client, tokens)
    headers = bearer(tokens["access_token"])
    assert client.delete(f"/api-keys/{created['prefix']}", headers=headers).status_code == 204
    response = client.get("/partner/reports", headers={"X-API-Key": created["key"]})
    assert response.status_code == 401


def test_expired_key_is_rejected(client, tokens):
    created = new_key(client, tokens, expires_in_days=1)
    with freeze_time(time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 86400))):
        response = client.get("/partner/reports", headers={"X-API-Key": created["key"]})
    assert response.status_code == 401


def test_cannot_revoke_another_users_key(client, tokens):
    created = new_key(client, tokens)
    client.post("/auth/register", json={"email": "other@example.com", "password": PASSWORD})
    other = client.post(
        "/auth/login", data={"username": "other@example.com", "password": PASSWORD}
    ).json()
    response = client.delete(
        f"/api-keys/{created['prefix']}", headers=bearer(other["access_token"])
    )
    assert response.status_code == 404
