"""Passkeys (WebAuthn): login with a key that stays on the user's device.

There is no shared secret to steal, and the browser signs for the real site's domain only, so
a look-alike phishing site cannot get a valid response.
"""

import json
import secrets

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from apps.app1_jwt.deps import ClaimsDep, KeyRingDep, StoreDep, TokenPair, issue_pair
from apps.app1_jwt.settings import settings

router = APIRouter(tags=["Passkeys"])
CHALLENGE_TTL_SECONDS = 300


class RegistrationResult(BaseModel):
    credential: dict


class LoginResult(BaseModel):
    challenge_id: str
    credential: dict


@router.post("/passkeys/register/options")
async def registration_options(claims: ClaimsDep, store: StoreDep) -> dict:
    user = await store.get_user_by_id(claims.user_id)
    options = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name="Auth Course",
        user_id=claims.user_id.encode(),
        user_name=user["email"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    challenge = bytes_to_base64url(options.challenge)
    # Single-use, so a captured response cannot be replayed.
    await store.save_single_use("passkey_reg", claims.user_id, challenge, CHALLENGE_TTL_SECONDS)
    return json.loads(options_to_json(options))


@router.post("/passkeys/register/verify", status_code=status.HTTP_201_CREATED)
async def register(body: RegistrationResult, claims: ClaimsDep, store: StoreDep) -> dict[str, str]:
    challenge = await store.take_single_use("passkey_reg", claims.user_id)
    if challenge is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Challenge expired")
    try:
        verified = verify_registration_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=settings.rp_id,
            expected_origin=settings.origin,
        )
    except InvalidRegistrationResponse as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Passkey was not accepted") from exc

    await store.save_passkey(
        claims.user_id,
        bytes_to_base64url(verified.credential_id),
        {
            "public_key": bytes_to_base64url(verified.credential_public_key),
            "sign_count": verified.sign_count,
        },
    )
    return {"message": "Passkey saved"}


@router.post("/passkeys/login/options")
async def login_options(store: StoreDep) -> dict:
    options = generate_authentication_options(
        rp_id=settings.rp_id, user_verification=UserVerificationRequirement.PREFERRED
    )
    challenge_id = secrets.token_urlsafe(16)
    await store.save_single_use(
        "passkey_login",
        challenge_id,
        bytes_to_base64url(options.challenge),
        CHALLENGE_TTL_SECONDS,
    )
    return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}


@router.post("/passkeys/login/verify")
async def login(body: LoginResult, store: StoreDep, ring: KeyRingDep) -> TokenPair:
    challenge = await store.take_single_use("passkey_login", body.challenge_id)
    passkey = await store.get_passkey(body.credential.get("id", ""))
    if challenge is None or passkey is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Passkey was not accepted")
    try:
        verified = verify_authentication_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=settings.rp_id,
            expected_origin=settings.origin,
            credential_public_key=base64url_to_bytes(passkey["public_key"]),
            # A counter that goes backwards can mean the key was cloned.
            credential_current_sign_count=passkey["sign_count"],
        )
    except InvalidAuthenticationResponse as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Passkey was not accepted") from exc

    await store.save_passkey(
        passkey["user_id"],
        body.credential["id"],
        {"public_key": passkey["public_key"], "sign_count": verified.new_sign_count},
    )
    return await issue_pair(store, ring, passkey["user_id"])


@router.get("/passkeys/demo", response_class=HTMLResponse)
def demo_page() -> str:
    return """<!doctype html>
<title>Passkey demo</title>
<h1>Passkey demo</h1>
<p>Open this at http://localhost:8001/passkeys/demo. Sign in through the API first, and
paste your access token here to add a passkey.</p>
<input id="token" placeholder="Access token" size="60">
<button id="add">Add a passkey</button>
<button id="login">Sign in with a passkey</button>
<pre id="out"></pre>
<script>
const out = document.getElementById("out");
const post = (url, body, token) => fetch(url, {
  method: "POST",
  headers: {"Content-Type": "application/json",
            ...(token ? {Authorization: "Bearer " + token} : {})},
  body: JSON.stringify(body || {}),
}).then(r => r.json());

document.getElementById("add").onclick = async () => {
  const token = document.getElementById("token").value;
  const options = await post("/passkeys/register/options", {}, token);
  const created = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options)});
  const result = await post("/passkeys/register/verify",
                            {credential: created.toJSON()}, token);
  out.textContent = JSON.stringify(result);
};

document.getElementById("login").onclick = async () => {
  const start = await post("/passkeys/login/options");
  const assertion = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(start.options)});
  const result = await post("/passkeys/login/verify",
    {challenge_id: start.challenge_id, credential: assertion.toJSON()});
  out.textContent = result.access_token ? "Signed in with a passkey." : JSON.stringify(result);
};
</script>"""
