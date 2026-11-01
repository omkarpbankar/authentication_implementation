# Phase 7: SSO, SAML, and Provisioning

**Goal:** Let one login open many apps, as companies expect.
**You will build:** App 6, two apps sharing one login, one with OIDC and one with SAML.

## The big idea

Think of a theme park pass. You buy it once at the gate, then ride everything without paying again. **Single Sign-On** works like this: you sign in once at the identity provider, and each app trusts that.

There are three separate sessions to keep in mind:

| Session | Where it lives |
|---|---|
| IdP session | At the login server |
| App session | In each app |
| Token lifetime | In each token |

Logging out of one does not automatically end the others, which is why logout is hard.

**SAML** is an older standard for the same goal, and it is still common in large companies. It sends signed XML through the browser. The app is called the **Service Provider (SP)**.

## Learn in this order

1. **Session layers.** See why one login reaches many apps.
2. **SAML parts.** Assertion, metadata, EntityID, and the ACS URL.
3. **SP-initiated vs IdP-initiated.** Starting at the app is safer than starting at the IdP.
4. **Assertion checks.** Signature, audience, time window, and `InResponseTo`.
5. **Brokering.** Your app trusts one broker, which trusts many IdPs.
6. **Provisioning.** Just-in-time creates users at login. SCIM also removes them when they leave.
7. **Logout.** Single Logout and back-channel logout.

## What you will build

Connect two apps to one Keycloak session, build a SAML app, inspect real assertions, connect Entra ID, add a SCIM endpoint, and try SAML attacks that must all fail.

## Run it

The code is in [apps/app6_sso/](../apps/app6_sso/).

```powershell
docker compose --profile saml up -d --build saml-app
uv run uvicorn apps.app6_sso.oidc_app:app --port 8006
```

Open http://localhost:8006/login and sign in as `asha`. Then open http://localhost:8007/saml/login, and notice that there is no second sign-in.

```powershell
uv run python scripts/live_phase7.py
docker compose --profile saml run --rm --no-deps saml-app pytest tests/app6_saml -v
```

The second command is the SAML attack lab.

**Learned while building:**

- Keycloak's default role setting repeats an attribute name, and strict SAML libraries reject that. The right fix is to change what the IdP sends, not to weaken the check.
- A rejected assertion once caused a 500 error. A bad message should always be a clean refusal, and there is now a test for it.

## Small test

Pass mark: 4 of 5.

**1. Why doesn't logging out of one app always end your SSO?**

<details><summary>Answer</summary>

The app session and the IdP session are separate. If the IdP session lives on, the next app can sign you in again.

</details>

**2. What is a SAML assertion?**

<details><summary>Answer</summary>

A signed XML statement from the IdP saying who the user is, with attributes and conditions for when it is valid.

</details>

**3. Why is IdP-initiated SSO riskier?**

<details><summary>Answer</summary>

The app did not ask for that login, so it cannot match the response to a request. That makes injected or replayed assertions harder to detect.

</details>

**4. Why might a company need SCIM as well as just-in-time provisioning?**

<details><summary>Answer</summary>

Just-in-time only creates users at login. SCIM also updates and deactivates them when they change roles or leave.

</details>

**5. Why use a maintained library rather than parsing SAML yourself?**

<details><summary>Answer</summary>

XML signature validation is easy to get wrong, and attacks like signature wrapping exploit those mistakes.

</details>
