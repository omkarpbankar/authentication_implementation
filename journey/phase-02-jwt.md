# Phase 2: JWT From First Principles

**Goal:** Understand what a token is by building one by hand.
**You will build:** App 1, a user API with login, refresh tokens, and key rotation.

## The big idea

A JWT is like a tamper-proof festival wristband. Staff can check it at any gate without calling head office, because the seal proves it is genuine. That is also the weakness: once issued, it works until it expires, even if head office wants it cancelled.

A JWT has three parts separated by dots:

```
header.payload.signature
```

- **Header:** which signing method was used.
- **Payload:** the claims, such as user ID and expiry.
- **Signature:** proof that nothing was changed.

**The payload is signed, not encrypted.** Anyone holding a token can read it, so never put secrets in it.

## Learn in this order

1. **Claims.** `sub` is who, `iss` is who issued it, `aud` is who it is for, and `exp` is when it expires.
2. **Signing.** HS256 uses one shared secret. RS256 and ES256 use a private key to sign and a public key to verify.
3. **Access and refresh tokens.** Access tokens live for minutes. Refresh tokens last longer, and only get new access tokens.
4. **Rotation.** Each refresh issues a new refresh token. Reuse of an old one signals theft, so the whole family is cancelled.
5. **Revocation.** Short lifetimes plus a small denylist give you most of the control sessions offer.
6. **JWKS.** A public URL that shares verification keys, so other services need no secret.

## What you will build

Create a JWT by hand with only Python's standard library, add login with Argon2id, add refresh rotation and logout, move to RS256, then rotate keys with no user being signed out.

You will also try attacks such as forged tokens, `alg: none`, and tokens meant for another API. Each one must fail.

## Run it

The code is in [apps/app1_jwt/](../apps/app1_jwt/).

```powershell
docker compose up -d --wait
uv run python -m apps.app1_jwt.manual_jwt
uv run uvicorn apps.app1_jwt.main:app --port 8001
```

Try the API at http://localhost:8001/docs. Then watch the whole flow run on its own:

```powershell
uv run python scripts/live_phase2.py
uv run pytest tests/app1_jwt/test_attacks.py -v
```

**Read this first:** `manual_jwt.py` is the most useful 60 lines in this phase.

**Learned while building:** Keeping the app's own tokens separate from refresh tokens makes rotation easy, because a refresh token is random and holds no data.

## Small test

Pass mark: 4 of 5.

**1. Is it safe to store a user's home address in a JWT payload? Why?**

<details><summary>Answer</summary>

No. The payload is only encoded, so anyone with the token can read it. Signing proves it was not changed, but does not hide it.

</details>

**2. What is the difference between `iss` and `aud`?**

<details><summary>Answer</summary>

`iss` says who created the token. `aud` says who it was created for. Checking `aud` stops a token meant for one API from being used on another.

</details>

**3. Why keep access tokens short-lived?**

<details><summary>Answer</summary>

A stolen JWT works until it expires, so a short lifetime limits the damage. Refresh tokens keep the user signed in without a long-lived access token.

</details>

**4. When would you choose RS256 over HS256?**

<details><summary>Answer</summary>

When other services must verify tokens. They need only the public key, and cannot create tokens. With HS256, every verifier holds the secret and could forge tokens.

</details>

**5. A refresh token that was already used shows up again. What should the server do, and why?**

<details><summary>Answer</summary>

Cancel the whole token family. It cannot tell whether the user or a thief holds the newer token, so it forces a fresh login.

</details>
