# Phase 3: OAuth 2 and OpenID Connect

**Goal:** Let a trusted login server handle sign-in for your app.
**You will build:** App 2, a web app secured by your local Keycloak.

## The big idea

A hotel valet key starts the car but cannot open the boot. You hand over limited access without giving away your main key. **OAuth 2** works the same way: an app gets limited access without ever seeing your password.

OAuth was designed for *access*, not for telling an app who you are. **OpenID Connect (OIDC)** adds that part, with an **ID token** that says who signed in.

| Token | For whom | Says |
|---|---|---|
| ID token | Your app | Who signed in |
| Access token | An API | What the caller may do |
| Refresh token | The login server | Please issue new tokens |

## Learn in this order

1. **The roles.** The user, the client app, the login server, and the API.
2. **The Authorization Code flow.** The app sends you to the login server, you sign in there, and you return with a short-lived code that the app swaps for tokens.
3. **Protective values.** `state` stops login CSRF, `nonce` ties the ID token to this login, and PKCE stops a stolen code from being used.
4. **Scopes.** Named permissions an app requests.
5. **Backend-for-Frontend.** The server keeps the tokens, and the browser holds only a session cookie.
6. **Other flows.** Client Credentials for machines, Device flow for CLIs and TVs.
7. **OAuth vs OIDC.** GitHub login gives you OAuth, with no ID token.

## What you will build

Write the whole login by hand once, then rewrite it with Authlib to see what the library does for you. Then protect an API, add machine-to-machine access, build a small device-login CLI, and add GitHub login through Keycloak.

## Run it

The code is in [apps/app2_oidc/](../apps/app2_oidc/). Practice accounts are `asha` and `ravi`, with the password `correct-horse-battery`.

```powershell
uv run python scripts/reset_realm.py
uv run uvicorn apps.app2_oidc.manual_flow:app --port 8002
```

Open http://localhost:8002 and sign in. To see everything run, including the worker and device login:

```powershell
uv run python scripts/live_phase3.py
```

**Learned while building:** Tests with a fake provider all passed, yet about 1 real login in 12 failed. Docker's clock ran slightly behind, so a token could look like it came from the future. That is why token checks allow 30 seconds of clock difference. See `CLOCK_SKEW_SECONDS` in `oidc.py`.

**Your step:** Adding GitHub through Keycloak needs a free GitHub OAuth app. See [the checklist](CHECKLIST.md).

## Small test

Pass mark: 4 of 5.

**1. What does OIDC add on top of OAuth 2?**

<details><summary>Answer</summary>

Identity. It gives the app an ID token that says who signed in, while OAuth alone only grants access.

</details>

**2. Why does the login flow return a code, rather than tokens directly in the browser's URL?**

<details><summary>Answer</summary>

URLs leak through history, logs, and referrers. The code is short-lived and useless alone, and the server swaps it for tokens over a direct connection.

</details>

**3. What attack does PKCE stop?**

<details><summary>Answer</summary>

Use of a stolen authorization code. Without the secret verifier created at the start of the flow, the attacker cannot exchange the code.

</details>

**4. Should your API accept an ID token as its credential? Why?**

<details><summary>Answer</summary>

No. An ID token tells the client who signed in. APIs should receive access tokens issued for them.

</details>

**5. Why keep tokens on the server in the Backend-for-Frontend pattern?**

<details><summary>Answer</summary>

Browser JavaScript can be attacked by XSS. If tokens stay on the server, the browser holds only an `HttpOnly` session cookie, so a script cannot copy them.

</details>
