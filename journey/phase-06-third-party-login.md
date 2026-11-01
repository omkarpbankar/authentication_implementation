# Phase 6: Third-Party Login

**Goal:** Offer "Sign in with Google" and similar buttons safely.
**You will build:** App 5, one account linked to several providers.

## The big idea

Third-party login is like a bouncer accepting a government ID instead of issuing their own membership card. You trust someone else's check, so your app stores no password for that user.

The hard part is not the button. It is deciding **when two logins are the same person**.

## Learn in this order

1. **Stable identifiers.** Use the issuer plus `sub`, because emails can change and be reassigned.
2. **`email_verified`.** Unverified emails must never link to an existing account.
3. **Provider differences.** Google and Microsoft use OIDC. GitHub uses OAuth, so you fetch the profile from its API.
4. **Account linking.** Link only when the user is signed in and has re-authenticated.
5. **Account pre-hijacking.** An attacker creates an account using your email before you sign up, then waits.
6. **Login vs delegated access.** Signing in with Google differs from reading someone's Google Calendar.
7. **Build vs buy.** When Auth0, Clerk, or Firebase Auth makes more sense.

## What you will build

Add Google, Microsoft, and GitHub login, then a provider registry, safe linking and unlinking, and read-only Google Calendar access with an encrypted refresh token.

## Run it

The code is in [apps/app5_social/](../apps/app5_social/). Keycloak stands in as a third-party provider, so this works with no accounts.

```powershell
uv run uvicorn apps.app5_social.main:app --port 8005
```

Open http://localhost:8005, or run the whole flow with `uv run python scripts/live_phase6.py`.

**Your step:** Add real providers with [the setup guide](../apps/app5_social/SETUP.md). Google, Microsoft, and GitHub have only been tested with simulated responses.

## Small test

Pass mark: 4 of 5.

**1. Why identify a user by issuer and `sub`, rather than email?**

<details><summary>Answer</summary>

Emails can change or be reassigned to another person. The issuer and `sub` pair stays stable for that account.

</details>

**2. A new login has the same email as an existing account. Should you merge them automatically?**

<details><summary>Answer</summary>

No. It could be an account takeover. Linking should require a verified email and a signed-in user who re-authenticates.

</details>

**3. Why does GitHub need different code from Google?**

<details><summary>Answer</summary>

GitHub login uses OAuth, with no ID token. You call its API for the profile and verified emails.

</details>

**4. Why block unlinking a user's last login method?**

<details><summary>Answer</summary>

They would have no way to sign in, and would be locked out.

</details>

**5. What is the difference between signing in with Google and reading a user's Google Calendar?**

<details><summary>Answer</summary>

Signing in tells your app who the user is. Reading the calendar is delegated access to their data, which needs an extra scope and their consent.

</details>
