# Phase 10: Other Login Methods

**Goal:** Add the stronger and more specialized methods real systems use.
**You will build:** Extensions to Apps 1 and 7.

## The big idea

Passwords alone are weak, because they can be guessed, reused, and phished. Different situations also need different credentials. A person, a partner's script, and a background service should not all log in the same way.

| Method | Good for | In plain words |
|---|---|---|
| **TOTP** | Second factor | A six-digit code from an app |
| **Passkeys** | Phishing-resistant login | Your device signs a challenge |
| **Magic links** | Passwordless login | A one-time link by email |
| **API keys** | Scripts and partners | A long secret for programs |
| **mTLS** | Service-to-service | Both sides present certificates |

## Learn in this order

1. **TOTP.** The app and server share a secret, and both compute the same code from the time.
2. **Recovery codes.** What happens when someone loses their phone.
3. **Passkeys.** A private key stays on your device, and it is tied to the real website.
4. **Magic links and password reset.** Single-use, short-lived, and stored hashed.
5. **API keys.** Prefixed, hashed, scoped, and revocable.
6. **Service identity.** Client credentials and mTLS.
7. **Concept notes.** LDAP, Kerberos, workload identity, DPoP, and token exchange.

## What you will build

Add TOTP with recovery codes, passkeys, magic links, secure password reset, and API keys, and then run a small mTLS lab.

## Run it

These features are in App 1, in `mfa.py`, `passkeys.py`, `links.py`, and `api_keys.py`. The mTLS lab is in [apps/mtls_lab/](../apps/mtls_lab/).

```powershell
docker compose up -d --wait
uv run python -m apps.mtls_lab.make_certs
uv run python scripts/live_phase10.py
```

Emails go to Mailpit, which catches everything locally, so you can read them at http://localhost:8025.

**Try a real passkey:** Passkeys were tested with a software authenticator, not a real device. Start App 1, open http://localhost:8001/passkeys/demo, and use your own device.

## Concept notes

These do not need building, but you will meet them at work.

| Term | In plain words |
|---|---|
| **LDAP** | An older way to look up people in a company directory, often Active Directory. Many apps once checked passwords against it directly. |
| **Kerberos** | How Windows networks sign you in once. A central server issues tickets, so your password does not travel to each service. |
| **Workload identity** | Cloud services prove who they are using the platform, so no secret is stored. AWS IRSA and Azure Managed Identity are examples. |
| **DPoP** | Ties a token to a key held by the client, so a stolen token alone is useless. |
| **Token exchange** | RFC 8693. A service swaps one token for another, such as to call the next API on a user's behalf. Entra's On-Behalf-Of from Phase 4 is similar. |

## Small test

Pass mark: 4 of 5.

**1. Why do passkeys resist phishing when passwords do not?**

<details><summary>Answer</summary>

The private key never leaves the device, and the browser ties the credential to the real site. A fake site cannot trigger a valid signature.

</details>

**2. Why must recovery codes be single-use and stored hashed?**

<details><summary>Answer</summary>

They bypass MFA, so a leaked database must not reveal them, and a used code must not work twice.

</details>

**3. Why store only a hash of an API key?**

<details><summary>Answer</summary>

If the database leaks, attackers still cannot use the keys. The full key is shown only once, when created.

</details>

**4. What should password reset do to existing sessions?**

<details><summary>Answer</summary>

End them, since the reset may be happening because someone else got in.

</details>

**5. Why shouldn't a background service log in with a person's account?**

<details><summary>Answer</summary>

It breaks when that person leaves, it blurs the audit trail, and it usually gives far more access than the service needs.

</details>
