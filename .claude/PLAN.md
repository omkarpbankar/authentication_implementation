# Authentication and Authorization Learning Plan

**Status:** All phases are built. See `journey/CHECKLIST.md` for how each was verified, and for steps that need your own accounts. Lessons and tests are in `journey/`.
**Goal:** Understand how modern identity works, build it yourself in FastAPI, and finish with one production-grade application.
**Fast-changing facts last checked:** 2026-11-01

---

## 1. Overview

### Roadmap

```
FOUNDATIONS        AUTHENTICATION                     FEDERATION              PLATFORM AND PRODUCTION
-----------        --------------                     ----------              -----------------------
Phase 0  Setup     Phase 2  JWT            -> App 1   Phase 6  Third-party    Phase 8   Tenants and RLS  -> App 7
Phase 1  Concepts  Phase 3  OAuth 2 / OIDC -> App 2            login -> App 5 Phase 9   RBAC and beyond  -> App 7
                   Phase 4  Entra ID       -> App 3   Phase 7  SSO and SAML   Phase 10  MFA, passkeys, M2M
                   Phase 5  AWS Cognito    -> App 4            -> App 6       Phase 11  App access, admin panel -> App 8
                                                                              Phase 12  Production hardening
```

### Progress

| Phase | Topic | Output | Estimate | Built |
|---|---|---|---|---|
| 0 | Workspace setup | Repo, Docker stack, dependencies | 3 h | [x] |
| 1 | Identity fundamentals | Concept notes, 3 small exercises | 6 h | [x] |
| 2 | JWT from first principles | App 1: `app1_jwt` | 14 h | [x] |
| 3 | OAuth 2 and OpenID Connect | App 2: `app2_oidc` | 14 h | [x] |
| 4 | Microsoft Entra ID (Azure AD) | App 3: `app3_entra` | 10 h | [x] |
| 5 | AWS Cognito | App 4: `app4_cognito` | 10 h | [x] |
| 6 | Third-party login: Google and others | App 5: `app5_social` | 8 h | [x] |
| 7 | SSO, SAML, and provisioning | App 6: `app6_sso` | 14 h | [x] |
| 8 | Multi-tenancy, tenant ID, row-level security | App 7: `app7_platform` (tenancy) | 12 h | [x] |
| 9 | Authorization: RBAC, ABAC, ReBAC | App 7: `app7_platform` (permissions) | 12 h | [x] |
| 10 | Other authentication methods | Extensions to Apps 1 and 7 | 8 h | [x] |
| 11 | Application access, user tiers, admin panel | App 8: `app8_access` | 18 h | [x] |
| 12 | Production hardening | Apps 7 and 8 finished | 14 h | [x] |

The total is about 143 hours, or roughly 18 weeks at 8 hours a week. These are my estimates, so adjust them as you learn your pace.

### Key decisions

| Decision | Why |
|---|---|
| **Six focused apps, plus two larger builds** | Apps 1 to 4 are the 3 to 4 apps you first asked for. Apps 5 and 6 add third-party login and SSO. App 7 applies tenancy, RBAC, and production work to a realistic app. App 8 is the full access-control system: three applications, an access service, and an admin panel. |
| **A central access service decides who can use each application** | Every app asks one service, so one admin panel controls everything and revocation is fast. This is the same split used by policy systems such as AuthZEN, with admin, decision, and enforcement kept separate. |
| **Access is denied by default** | A signed-in user with no grant gets your "not authorized" message, never a default tier. |
| **Tiers live in the database, not in the token** | A changed tier takes effect within seconds, instead of when the token expires. |
| **Basic, Standard, and Premium are entitlements, not roles** | A tier says what the product includes for a user. A role says what they may do within a tenant. Both must pass. |
| **The admin panel uses FastAPI, Jinja2, and plain forms** | This keeps the frontend small, and server-rendered forms suit an internal tool. It was planned with `htmx`, which turned out to be unnecessary. |
| **Keycloak is the first SAML IdP, then Entra ID** | Keycloak is free and local, so you can inspect both sides of SAML before adding a cloud provider. |
| **The SAML app runs in a Linux container** | `python3-saml` depends on `xmlsec`, which has a history of Windows install failures. A container avoids that problem. |
| **`tenant_id` is your own internal ID** | Every IdP identifies tenants differently, or not at all, so each is mapped to one internal value. |
| **Row-level security backs up application checks** | The app still filters by tenant, and Postgres enforces the same rule if a query misses it. |
| **Keycloak runs locally before any cloud provider** | It is free and works offline, and you can see every setting. Entra ID and Cognito are then easier because the concepts already make sense. |
| **Build the OIDC flow by hand once, then use a library** | Writing it once shows what libraries do for you. Real apps should use the library. |
| **Server-rendered pages (Jinja2) instead of React** | The learning target is identity, not frontend work. Redirects and cookies are just as visible this way. |
| **One `pyproject.toml` and your existing `.venv`** | This keeps setup simple. Apps are run separately, each on its own port. |
| **"Azure AD" appears as "Microsoft Entra ID"** | Microsoft renamed it, and current docs and portals use the new name. |
| **Local Docker deployment at the end, with cloud deployment optional** | It teaches almost all of the hardening at no cost. |

### Rules for every app

1. Each app has a `README.md` covering how to run it, the flow, and what it taught you.
2. Tests must include **failure cases**: expired, forged, wrong audience, wrong role. In security code, proving what gets rejected matters more than proving what succeeds.
3. Secrets stay in `.env`, which is git-ignored. Only `.env.example` is committed.
4. Use test users and dev credentials only, never real personal accounts for test data.
5. Tear down paid cloud resources at the end of each lab that uses them.

---

## 2. Authentication Methods Map

### Terms to keep straight

| Term | Question it answers | Example |
|---|---|---|
| **Authentication (AuthN)** | Who are you? | Password plus TOTP login |
| **Authorization (AuthZ)** | What may you do? | Only `editor` can update a document |
| **OAuth 2** | How does an app get delegated access? | An app reads your calendar without your password |
| **OpenID Connect (OIDC)** | How does an app learn who signed in? | "Sign in with Microsoft" |
| **SAML 2.0** | How does older enterprise SSO work? | Corporate login to a SaaS product |
| **JWT** | What format can a signed token use? | A format, not a protocol or a login method |
| **Identity Provider (IdP)** | Who runs login and issues tokens? | Entra ID, Cognito, Keycloak |
| **Service Provider (SP)** | Which application relies on the IdP in SAML? | Your FastAPI app |
| **Single Sign-On (SSO)** | How does one login reach many apps? | One company login opens mail and HR tools |
| **Federation** | How do separate organizations trust each other's logins? | Your app accepts a customer's Entra ID login |
| **Tenant** | Which customer or organization owns this data? | Acme Corp inside your SaaS product |
| **Tenant ID** | How is that tenant identified? | Entra's `tid`, or your own `tenant_id` column |
| **Row-Level Security (RLS)** | Which database rows may this session touch? | Postgres returns only the current tenant's rows |
| **Application ID** | Which application is this? | A permanent ID for the Notes app |
| **Client ID** | Which app is talking to the IdP? | Entra calls this the "Application (client) ID" |
| **Entitlement** | What does this user's access include? | Premium includes PDF export |
| **Access tier** | At what level can this user use the app? | Basic, Standard, or Premium |

### Method coverage

| Method | Typical use | Depth | Phase |
|---|---|---|---|
| Passwords with Argon2id | First-party login | Build | 2 |
| Server-side sessions and cookies | Traditional web apps | Build | 1, 3 |
| HTTP Basic | Legacy and internal tools | Exercise | 1 |
| JWT access and refresh tokens | APIs | Build | 2 |
| OAuth 2 Authorization Code + PKCE | Web, mobile, and SPA login | Build | 3 |
| OIDC | Federated login and SSO | Build | 3 |
| OAuth 2 Client Credentials | Service-to-service | Build | 3, 4, 5 |
| OAuth 2 Device Authorization | CLIs, TVs, devices | Build | 3 |
| Token Exchange and On-Behalf-Of | API calling another API as the user | Build | 4 |
| Microsoft Entra ID | Workforce and enterprise identity | Build | 4 |
| Amazon Cognito | Customer identity on AWS | Build | 5 |
| Google login | Consumer and Workspace users | Build | 6 |
| Microsoft personal account login | Consumer users | Build | 6 |
| GitHub login | Developer tools | Build | 3, 6 |
| LinkedIn and Facebook login | Professional and consumer apps | Optional | 6 |
| Sign in with Apple | Apps on Apple platforms | Concept | 6 |
| Hosted platforms (Auth0, Okta, Clerk, WorkOS, Firebase Auth, Supabase Auth) | Buying auth instead of building it | Comparison | 6 |
| Web SSO across applications | One login for many apps | Build | 7 |
| SAML 2.0 | Enterprise SSO | Build | 7 |
| Identity brokering | One app, many enterprise IdPs | Build | 7 |
| Just-in-time provisioning | Creating users at first login | Build | 7 |
| SCIM | Automated user provisioning | Build | 7 |
| Single Logout and back-channel logout | Ending sessions across apps | Build | 7 |
| Home realm discovery | Routing users to the right IdP | Build | 7, 8 |
| TOTP MFA | Second factor | Build | 10 |
| Passkeys / WebAuthn | Phishing-resistant login | Build | 10 |
| Magic links and email OTP | Passwordless login | Build | 10 |
| API keys | Developer and partner access | Build | 10 |
| mTLS | Zero-trust service-to-service | Lab | 10 |
| LDAP and Kerberos | On-premises directories | Concept | 10 |
| Workload identity (IRSA, Managed Identity) | Cloud workloads without secrets | Concept | 10 |
| DPoP | Sender-constrained tokens | Concept | 10 |

**Grants you will learn to avoid:** Implicit and Resource Owner Password Credentials. The OAuth 2.1 draft removes both and requires PKCE for authorization code flows. OAuth 2.1 is still an Internet-Draft, not an RFC, though RFC 9700 already gives similar security guidance for OAuth 2.0.

---

## 3. Target Repository Layout

```
Authentication/
├── .claude/
│   ├── PLAN.md
│   ├── settings.json         # Project permissions
│   └── skills/               # learning-coach, auth-implementer
├── .venv/
├── .env.example
├── .gitignore
├── pyproject.toml
├── docker-compose.yml        # Postgres (5433), Redis (6380), Keycloak (8080)
├── docs/                     # Your concept notes
├── journey/                  # Lessons and small tests, one file per phase
├── scripts/                  # Project helpers, such as creating .env
├── tests/                    # One folder per app
├── keycloak/realm-export.json
├── apps/
│   ├── phase1_fundamentals/  # Ports 8101 to 8104
│   ├── app1_jwt/             # Port 8001
│   ├── app2_oidc/            # Port 8002
│   ├── app3_entra/           # Port 8003
│   ├── app4_cognito/         # Port 8004
│   ├── app5_social/          # Port 8005
│   ├── app6_sso/             # Ports 8006 (OIDC app) and 8007 (SAML app, in a container)
│   ├── app7_platform/        # Port 8008
│   └── app8_access/
│       ├── access_service/   # Port 8010: access decisions and admin API
│       ├── admin_panel/      # Port 8011
│       ├── access_client/    # Shared enforcement code used by all three apps
│       ├── notes_app/        # Port 8012
│       ├── reports_app/      # Port 8013
│       └── files_app/        # Port 8014
└── infra/cognito.yaml        # CloudFormation for clean setup and teardown
```

Folder names start with `app`, not a number, because Python packages cannot start with a digit.

### Dependencies, added phase by phase

| Purpose | Package |
|---|---|
| API and server | `fastapi`, `uvicorn[standard]`, `pydantic-settings`, `jinja2`, `python-multipart` |
| JWT, including RSA and EC signing | `pyjwt[crypto]` |
| Password hashing | `pwdlib[argon2]` |
| Database | `sqlalchemy`, `alembic`, `asyncpg` |
| Cache, sessions, revocation | `redis` |
| OIDC client | `authlib`, `httpx`, `itsdangerous` |
| Entra ID | `msal` |
| AWS | `boto3` |
| SAML, inside the App 6 container only | `python3-saml` |
| MFA and passkeys | `pyotp`, `webauthn`, `segno` |
| Admin panel UI | `jinja2` |
| Testing | `pytest`, `httpx2`, `fakeredis`, `pytest-asyncio`, `respx`, `freezegun` |
| Hardening | `slowapi`, `structlog`, `ruff`, `bandit`, `pip-audit` |

FastAPI's own docs now use PyJWT and pwdlib with Argon2, so this plan does too. Exact versions get pinned when each package is installed.

---

## 4. Phases

### Phase 0: Workspace Setup

**Goal:** One command brings up everything that runs locally.

**Tasks**
- [x] Run `git init`, and add a `.gitignore` covering `.env`, `.venv`, and caches.
- [x] Create `pyproject.toml` and install base dependencies with `uv` into the existing `.venv`.
- [x] Write `docker-compose.yml` for Postgres, Redis, and Keycloak with a pinned image tag.
- [x] Set up `ruff` and `pytest`.
- [x] Confirm the toolchain works. Phase 1's running apps do this, so no separate `/health` skeleton was built.

**Accounts, needed later**

| Item | Needed by | Current state |
|---|---|---|
| Docker | Phase 0 | Installed, version 29.9.2 |
| uv, Python 3.11 | Phase 0 | Installed |
| AWS CLI | Phase 5 | Installed, credentials not checked |
| AWS account and budget alert | Phase 5 | Your action |
| Azure account with an Entra tenant | Phase 4 | Your action |
| Azure CLI | Phase 4 | Not installed, optional because the portal is enough |
| GitHub OAuth app | Phases 3 and 6 | Your action, free |
| Google Cloud OAuth client | Phase 6, and Phase 5 optional | Your action, free |
| Microsoft personal account app registration | Phase 6 | Your action, free |
| SAML-tracer browser extension | Phase 7 | Your action, free |
| Okta Integrator Free account | Phase 7, optional | Your action, free |

**Exit criteria**
- [x] `docker compose up -d` starts all three services healthy.
- [ ] You can log in to the Keycloak admin console.
- [x] `pytest` and `ruff check` both run.

---

### Phase 1: Identity Fundamentals

**Goal:** Understand the problems before reaching for tools.

**Concepts**
- Authentication factors: something you know, have, and are.
- HTTP statelessness and why sessions exist.
- Cookies: `HttpOnly`, `Secure`, `SameSite`, `Domain`, `Path`, and the `__Host-` prefix.
- Hashing, salting, encryption, encoding, and signing, and how they differ.
- Why Argon2id is used for passwords and SHA-256 is not.
- Stateful sessions vs stateless tokens.
- Core attacks: credential stuffing, session fixation, CSRF, XSS, token theft, phishing, user enumeration, replay.

**Exercises**
1. Protect an endpoint with HTTP Basic and capture the header. Note that Base64 is not encryption.
2. Build a server-side session login using Redis.
3. Reproduce a CSRF attack on your own local app, then fix it.

**Deliverable:** `docs/01-fundamentals.md`, written in your own words.

**Exit criteria**
- [ ] You can explain why a stolen JWT and a stolen session ID differ in revocation.
- [ ] You can explain when `SameSite=Lax` does and does not stop CSRF.
- [ ] You can explain why password hashes need to be slow.

---

### Phase 2: JWT From First Principles

**App 1: `app1_jwt`**, a user API with first-party login and no external IdP.

**Concepts**
- JWT structure: header, payload, signature, and the JWS, JWE, JWK, and JWA standards.
- Registered claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.
- HS256 for one service, RS256 and ES256 when other services verify tokens.
- JWKS and key rotation with `kid`.
- Access vs refresh tokens and their lifetimes.
- Why JWTs are hard to revoke, and the workarounds.
- Where to store tokens: API clients vs browsers.
- Payloads are signed but readable, so sensitive data does not belong in them.

**Build sequence**
1. **Manual JWT:** Create and verify an HS256 token using only `hmac`, `hashlib`, and `base64`. This small script is the most useful 30 minutes of the phase.
2. **Registration and login:** `POST /auth/register` and `POST /auth/login` with Argon2id.
3. **Protected routes:** `GET /users/me` using FastAPI dependencies.
4. **Refresh rotation:** `POST /auth/refresh` issues a new pair on each use and stores refresh tokens hashed.
5. **Reuse detection:** Replaying an old refresh token revokes that entire token family.
6. **Logout:** `POST /auth/logout` revokes the family and adds the access token's `jti` to a Redis denylist until it expires.
7. **Asymmetric signing:** Move to RS256 and publish `GET /.well-known/jwks.json`.
8. **Key rotation:** Run two keys at once, so old tokens verify while new ones use the new key.
9. **Second service:** A tiny separate API verifies tokens using only the JWKS URL.

**Attack lab: write each as a test that must fail authentication**

| Attack | Defense |
|---|---|
| `alg: none` token | Fixed algorithm allowlist |
| RS256 to HS256 confusion, using the public key as a secret | Never take the algorithm from the token |
| Tampered payload | Signature verification |
| Expired token | `exp` check |
| Token meant for another API | `aud` check |
| Token from another issuer | `iss` check |
| Refresh token used as an access token | A `typ` or `token_use` claim |
| Replayed refresh token | Family revocation |
| Weak HS256 secret | Secret of 256 bits or more from a CSPRNG |
| Login response timing reveals valid emails | Hash a dummy password for unknown users |

**Exit criteria**
- [ ] You can decode a JWT by hand and state which checks matter.
- [ ] All attack tests pass, meaning every attack gets rejected.
- [ ] The second service validates tokens without any shared secret.
- [ ] You can rotate signing keys with no user being logged out.

---

### Phase 3: OAuth 2 and OpenID Connect

**App 2: `app2_oidc`**, a web app and API secured by a local Keycloak realm.

**Concepts**
- Roles: resource owner, client, authorization server, resource server.
- Confidential vs public clients.
- Authorization Code + PKCE, step by step.
- What `state`, `nonce`, and `code_verifier` each prevent.
- Scopes vs claims, and consent.
- ID token vs access token vs refresh token.
- Discovery (`/.well-known/openid-configuration`) and UserInfo.
- Token introspection and revocation.
- Backend-for-Frontend (BFF) pattern for browser apps.
- SSO and logout, including RP-initiated and back-channel logout.
- OAuth vs OIDC, using GitHub as the example: GitHub login gives you OAuth, so there is no OIDC ID token to validate.

```
Browser            App 2                    Keycloak
  |-- GET /login -->|                          |
  |                 | create state, nonce, PKCE|
  |<-- 302 ---------|                          |
  |-- authorize + code_challenge ------------->|
  |<-- user signs in, 302 with code + state ---|
  |-- GET /callback ->|                        |
  |                 |-- code + code_verifier ->|
  |                 |<-- tokens ---------------|
  |                 | validate ID token, store tokens server-side
  |<-- session cookie only ----|               |
```

**Build sequence**
1. **Realm as code:** Create the realm, users, client, and roles, then export them to `keycloak/realm-export.json`.
2. **Hand-written flow:** Implement the diagram using only `httpx` and PyJWT.
3. **ID token validation:** Check signature, `iss`, `aud`, `exp`, and `nonce`.
4. **BFF sessions:** Keep tokens in Redis and give the browser only a session ID cookie.
5. **Library version:** Rewrite the login with Authlib and compare the two.
6. **Protected API:** Validate access tokens with cached JWKS, refetching on an unknown `kid`.
7. **Token refresh and logout:** Refresh silently, then end both the app and Keycloak sessions.
8. **Client Credentials:** A background worker calls the API with no user.
9. **Device flow:** A small CLI signs in through a browser on the side.
10. **Brokered social login:** Add GitHub as a Keycloak identity provider. Phase 6 covers connecting providers directly.

**Pitfalls to confirm by testing**
- Keycloak access tokens may lack your API in `aud` until you add an audience mapper.
- Starlette's `SessionMiddleware` signs cookies but does not encrypt them, so tokens must not go in it.
- PyJWT's `PyJWKClient` does blocking network calls, so it must not run directly in an async path.
- An ID token proves login to the client. It is not an API credential.

**Exit criteria**
- [ ] You can draw the Authorization Code + PKCE flow from memory.
- [ ] Removing the `state` check lets you demonstrate a login CSRF, and restoring it stops the attack.
- [ ] Your browser never receives an access token.
- [ ] All three flows work: browser, machine-to-machine, and device.
- [ ] You can explain when to choose the hand-written or library approach, and why production uses the library.

---

### Phase 4: Microsoft Entra ID (Azure AD)

**App 3: `app3_entra`**, enterprise sign-in and a protected API.

**Concepts**
- Tenants, users, groups, and how Microsoft's identity products relate.
- Tenant ID (`tid`), client ID, and object ID (`oid`), and where each one appears.
- App registration vs enterprise application (service principal).
- Delegated permissions (`scp`) vs application permissions (`roles`).
- Exposing an API, and app roles vs security groups.
- Single-tenant vs multi-tenant apps.
- v1 vs v2 tokens.
- Admin consent and Conditional Access. Conditional Access needs a paid license, so it is concept-only.
- Which product fits: Entra ID for workforce, **Entra External ID** for customers. Azure AD B2C closed to new customers on May 1, 2025, so it is not covered as a lab.

**Build sequence**
1. Create the web app and API registrations in the portal.
2. **User sign-in** using MSAL's auth code flow with a confidential client.
3. **Own API:** Expose `api://<client-id>/access_as_user` and validate its tokens.
4. **App roles:** Define `Reader` and `Writer`, assign them to test users, and enforce the `roles` claim.
5. **Daemon access:** Client credentials using the `/.default` scope.
6. **On-Behalf-Of:** Your API calls Microsoft Graph `/me` as the signed-in user.
7. **Multi-tenant check:** Validate `tid` against an allowlist.
8. **Optional:** Run the same login in an External ID tenant for a customer sign-up flow.

**Pitfalls to confirm by testing**
- Tokens meant for Microsoft Graph are not yours to validate, so your API needs its own scope.
- Without `requestedAccessTokenVersion: 2` in the app manifest, the issuer format differs from what you may expect.
- Users in too many groups get an overage indicator instead of a groups list.
- With multi-tenant apps, the issuer varies by tenant, so `tid` must be checked explicitly.

**Exit criteria**
- [ ] You can explain delegated vs application permissions using a token you decoded.
- [ ] A `Reader` gets 403 from a `Writer` route.
- [ ] The On-Behalf-Of call to Graph succeeds.
- [ ] You can decide between app roles and groups for a given app.

---

### Phase 5: AWS Cognito

**App 4: `app4_cognito`**, customer sign-up and sign-in on AWS.

**Concepts**
- User pools (authentication) vs identity pools (temporary AWS credentials).
- Feature plans: Lite, Essentials, Plus.
- App clients, domains, and managed login.
- Hosted login vs a custom UI calling the Cognito API.
- Groups, resource servers, and custom scopes.
- Lambda triggers across the authentication lifecycle.
- Federation with social and enterprise IdPs.
- Comparing Cognito with Entra ID and Keycloak, and when you would pick each.

**Build sequence**
1. Set a billing alert and deploy the user pool from `infra/cognito.yaml`.
2. **Managed login:** Authorization Code + PKCE with Authlib. Reuse what you built in Phase 3.
3. **Custom UI:** Sign-up, email confirmation, and login with `boto3`, then compare the tradeoffs.
4. **Token validation:** Write Cognito-specific checks.
5. **Groups:** Enforce `admin` and `member` through `cognito:groups`.
6. **Custom claims:** Add a claim with a Pre Token Generation Lambda.
7. **Machine-to-machine:** Add a resource server, custom scopes, and client credentials.
8. **Optional federation:** Add Google as an IdP.
9. **Optional identity pool:** Exchange a token for AWS credentials scoped to a per-user S3 prefix.
10. **Teardown:** Delete the stack and confirm that no resources remain.

**Pitfalls to confirm by testing**
- Cognito access tokens have `client_id` rather than `aud`, while ID tokens have `aud`. Generic validators can fail here.
- Always check `token_use`, so an ID token cannot be used as an access token.
- Cognito's logout endpoint is its own `/logout`, not a standard OIDC end-session flow.
- Customizing access tokens with the Lambda trigger requires Essentials or Plus.

**Cost guardrails**
- Lite and Essentials include 10,000 direct sign-in MAU free each month, and Plus has no free tier.
- Federated SAML and OIDC users get 50 MAU free.
- SMS costs extra, so this plan uses email and TOTP only.
- Machine-to-machine usage can be billed separately, so check the pricing page before Step 7.
- Stay on Essentials and do not enable Plus.

**Exit criteria**
- [ ] Sign-up, confirmation, login, refresh, and logout all work.
- [ ] An ID token used against the API is rejected.
- [ ] A Lambda-added claim appears in a decoded token.
- [ ] You can explain when an identity pool is needed.
- [ ] Teardown is complete, and your AWS bill shows nothing unexpected.

---

### Phase 6: Third-Party Login

**App 5: `app5_social`**, a sign-in page offering several providers, all linked to one user account.

**Concepts**
- Social login vs enterprise login.
- Why `email` is not a stable identifier, and why `iss` plus `sub` is.
- The `email_verified` claim, and why it matters before linking accounts.
- Account linking and the account pre-hijacking attack.
- Google specifics: consent screen, test users, Workspace vs consumer accounts, and the `hd` claim.
- Requesting minimal scopes, and using incremental consent for more.
- Login vs delegated access to a user's provider data.
- Build vs buy: when a hosted auth platform is the better choice.

**Provider coverage**

| Provider | Protocol | Cost | Depth |
|---|---|---|---|
| Google | OIDC | Free | Build |
| Microsoft personal accounts | OIDC | Free | Build |
| GitHub | OAuth 2, no ID token | Free | Build |
| LinkedIn | OIDC | Free | Optional |
| Facebook | OAuth 2 | Free | Optional |
| Apple | OIDC-based | Paid Apple Developer Program, confirm current terms | Concept |

**Build sequence**
1. **Data model:** A `users` table, plus an `identities` table unique on provider and subject.
2. **Google:** Authorization Code + PKCE with Authlib, followed by full ID token validation.
3. **Microsoft:** Add it almost entirely through configuration, which shows the value of a shared standard.
4. **GitHub:** Add a provider adapter that fetches the profile and verified emails through its API.
5. **Provider registry:** Adding a provider becomes one config entry and, when needed, one adapter.
6. **Account linking:** A signed-in user links a provider after re-authenticating. Matching emails never merge accounts automatically.
7. **Unlinking:** Block removal of a user's last remaining login method.
8. **Delegated access:** Request read-only Google Calendar access incrementally, and encrypt the stored refresh token.
9. **Build vs buy:** Write a one-page comparison of the hosted platforms from their current docs and pricing.

**Pitfalls to confirm by testing**
- A Google app in Testing mode is limited to listed test users, and its refresh tokens expire after 7 days.
- GitHub users can hide their email, so `/user/emails` may be needed.
- Trust the `hd` claim in the validated token. The `hd` request parameter only filters the sign-in UI.
- Provider-specific attributes differ, so tests should use recorded fixtures for each provider.

**Exit criteria**
- [ ] One user can sign in through Google, Microsoft, and GitHub and reach the same account.
- [ ] A user with a matching but unverified email cannot take over an account.
- [ ] Adding another OIDC provider takes only configuration.
- [ ] You can explain the difference between signing in with Google and accessing a user's Google data.

---

### Phase 7: SSO, SAML, and Provisioning

**App 6: `app6_sso`**, two small apps sharing one login: an OIDC app on port 8006 and a SAML app on port 8007.

**Concepts**
- The three session layers: IdP session, application session, and token lifetime.
- SSO vs federation vs reusing the same password.
- SAML parts: IdP, SP, assertion, metadata, EntityID, ACS URL, NameID, RelayState.
- SAML bindings: HTTP-Redirect and HTTP-POST.
- Signed responses vs signed assertions, plus assertion encryption.
- SP-initiated vs IdP-initiated SSO, and why IdP-initiated carries more risk.
- OIDC vs SAML, and when an enterprise customer will require each.
- Identity brokering: your app trusts one broker, which trusts many IdPs.
- Home realm discovery: routing a user by email domain.
- Just-in-time provisioning vs SCIM, and why deprovisioning is the hard part.
- Single Logout, OIDC back-channel logout, and their practical limits.
- Silent SSO with `prompt=none`, plus `max_age` and `acr` for forcing stronger login.
- Enforced SSO, domain verification, and emergency "break-glass" admin access.

```
Browser            SAML app (SP)                  IdP
  |-- GET /saml/login -->|                          |
  |<-- 302 + AuthnRequest + RelayState -------------|
  |-- AuthnRequest ---------------------------------->|
  |<-- user signs in, auto-POST form with assertion --|
  |-- POST /saml/acs --->|                          |
  |                      | validate signature, audience,
  |                      | time window, InResponseTo
  |<-- app session cookie|                          |
```

The browser carries everything, so the SP and IdP never need to call each other directly.

**Build sequence**
1. **OIDC SSO:** Connect two apps to one Keycloak realm. Signing in to one should sign you straight in to the other.
2. **Session inspection:** Look at each cookie, then compare local logout and global logout.
3. **SAML SP:** Build `/saml/metadata`, `/saml/login`, `/saml/acs`, and `/saml/logout` with `python3-saml` in strict mode.
4. **Assertion inspection:** Decode a real assertion using SAML-tracer.
5. **Attribute mapping:** Map assertion attributes to the user profile, and IdP groups to app roles.
6. **Mixed SSO:** A single Keycloak session signs the user in to both the OIDC and SAML apps.
7. **Entra ID as SAML IdP:** Create a custom enterprise application and connect it to your SP.
8. **Brokering:** Add Entra ID behind Keycloak, with no change to your app.
9. **Just-in-time provisioning:** Create users on first login and update their attributes on each login.
10. **SCIM:** Build `/scim/v2/Users` for create, update, and deactivate. Deactivating a user must end their sessions.
11. **Logout:** Add SAML Single Logout and OIDC back-channel logout, and handle failure cases.
12. **Optional:** Connect Okta as a second enterprise IdP.

**SAML attack lab: write each as a test that must be rejected**

| Attack | Defense |
|---|---|
| Unsigned or edited assertion | Require signatures, with strict validation |
| XML Signature Wrapping | Maintained library, using only the validated assertion |
| Replayed assertion | `InResponseTo`, `NotOnOrAfter`, and a store of used assertion IDs |
| Assertion for another SP | `AudienceRestriction` check |
| Wrong recipient | `Destination` and `Recipient` checks |
| Unsolicited IdP-initiated response | Disabled unless explicitly allowed |
| `RelayState` open redirect | Only allow relative, allowlisted paths |
| Malicious XML entities | Parser with external entities disabled |

**Pitfalls to confirm by testing**
- Never parse assertions yourself or read values from anything but the library's validated result.
- IdP certificates expire, so the SP should support two at once during rotation.
- Clock differences cause real login failures, so allow only a small, explicit skew.
- `NameID` can be an email that changes, so prefer a persistent identifier.

**Exit criteria**
- [ ] One sign-in reaches both apps, across OIDC and SAML.
- [ ] All SAML attack tests are rejected.
- [ ] You can read a SAML assertion and explain each security-relevant element.
- [ ] Your app can use Entra ID through brokering with no code changes.
- [ ] A SCIM deactivation blocks the user immediately, and you can demonstrate it.
- [ ] You can compare SAML and OIDC on one page.

---

### Phase 8: Multi-Tenancy, Tenant ID, and Row-Level Security

**App 7: `app7_platform`**, a multi-tenant project and document API. Tenants own projects and documents, and users join tenants through memberships.

**Concepts**
- Tenant vs user vs membership, including users who belong to several tenants.
- The two meanings of tenant ID: the **IdP's tenant ID** (such as Entra's `tid`) and **your application's `tenant_id`**.
- Isolation models and their tradeoffs.
- Tenant resolution from a subdomain, path, token claim, or header.
- Why a client-supplied tenant ID always needs a membership check.
- Tenant-scoped caches, queues, file storage, search, and logs.
- Tenant lifecycle: onboarding, suspension, export, and deletion.
- Noisy neighbors and per-tenant rate limits.
- Support access across tenants, with time limits and audit logs.

**Isolation models**

| Model | Isolation | Cost and effort | Best for |
|---|---|---|---|
| Shared tables with `tenant_id` and RLS | Good | Low | Most B2B SaaS. **Used in this plan.** |
| One schema per tenant | Better | Medium, as migrations multiply | Moderate tenant counts |
| One database per tenant | Strongest | High | Strict compliance or data residency |

**Tenant identifiers by source**

| Source | Tenant identifier | Notes |
|---|---|---|
| Entra ID | `tid` | Identifies the customer's directory |
| Keycloak | Organization claim, or a realm per tenant | Confirm the claim format against your pinned version |
| Cognito | None built in | Use a read-only custom attribute, a Lambda-added claim, or a pool per tenant |
| SAML | No standard field | Identify the tenant by the IdP's EntityID |
| Google | `hd` | Workspace accounts only |
| Your own tokens | `tenant_id` claim | Issued only after a membership check |

A `tenant_idp_connections` table maps each issuer and external ID to your internal `tenant_id`. If a Cognito custom attribute holds the tenant, users must not be able to write to it, or they can move themselves into another tenant.

**Row-level security design**

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON documents
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
```

```python
await session.execute(
    text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
    {"tenant_id": str(principal.tenant_id)},
)
```

| RLS rule | Why |
|---|---|
| App connects as a role that is not a superuser and lacks `BYPASSRLS` | Those roles skip policies, even with `FORCE` |
| App role does not own the tables, and migrations use a separate role | Owners skip policies unless `FORCE` is set |
| Set the tenant per transaction, with `set_config(..., true)` | A session-level value can leak to the next request on a pooled connection |
| No tenant set means no rows | Failures must deny access, not expose data |
| Include `WITH CHECK` | `USING` alone does not validate new row values on insert or update |
| Use `security_invoker = true` on views | Views can otherwise run with the owner's rights |
| Review all `SECURITY DEFINER` functions | They run with their owner's rights |
| Put `tenant_id` first in key indexes | Policies filter every query, so performance depends on it |
| Use composite foreign keys, such as `(tenant_id, project_id)` | A row cannot point to another tenant's parent |
| Make unique constraints per tenant | Two tenants can then use the same project name |

**Build sequence**
1. **Schema:** Create `tenants`, `users`, `memberships`, and `tenant_idp_connections`, with `tenant_id` on every tenant-owned table.
2. **Migrations and roles:** Use Alembic, with separate migration and application database roles.
3. **Tenant resolver:** A dependency produces a `TenantContext` only after confirming membership.
4. **IdP mapping:** Accept tokens from each IdP and map its identifier to your internal `tenant_id`.
5. **Tenant switching:** Users in several tenants choose one, and each token is valid for only that tenant.
6. **RLS policies:** Add policies to every tenant-owned table through migrations.
7. **Request wiring:** Set `app.tenant_id` at the start of each transaction, and confirm the SQLAlchemy approach during the build.
8. **Proof test:** Write a deliberately unfiltered query, and show Postgres still returns only the current tenant's rows.
9. **Beyond the database:** Prefix Redis keys, scope file paths, and pass tenant IDs through background jobs.
10. **Per-tenant SSO:** Route users by verified email domain to their tenant's IdP from Phase 7, with optional enforced SSO.
11. **Support access:** Add time-limited, audited cross-tenant access through a separate database role.
12. **Tenant lifecycle:** Add suspension, export, and deletion.

**Test approach:** Run a cross-tenant suite against every route, including reads, writes, and references to another tenant's IDs. Add a concurrency test proving that a pooled connection never carries one tenant's context into another tenant's request.

**Exit criteria**
- [ ] No request can read or change another tenant's data, even with application filters disabled.
- [ ] A forged or unauthorized tenant ID gets rejected.
- [ ] A query with no tenant set returns zero rows.
- [ ] The connection pool test passes under concurrent load.
- [ ] Tenants resolve correctly from Entra ID, Keycloak, Cognito, and SAML logins.
- [ ] You can explain why RLS supplements application checks rather than replacing them.

---

### Phase 9: Authorization: RBAC and Beyond

**App 7: `app7_platform`** continues here, adding permissions on top of the tenant model from Phase 8.

**Concepts**
- Authentication vs authorization boundaries, and 401 vs 403.
- RBAC: users, roles, permissions, and role hierarchy.
- Coarse roles in tokens vs fine-grained permissions in the database.
- Resource ownership and **BOLA/IDOR**, the top item in the OWASP API Security Top 10.
- Roles scoped to a tenant vs platform-wide roles.
- ABAC: decisions based on attributes.
- ReBAC: relationship-based access, as in Zanzibar and OpenFGA.
- Policy engines: Casbin, Open Policy Agent, OpenFGA, and when each is worth using.
- Delegation, admin boundaries, and privilege escalation.
- Permission changes vs long-lived tokens.

**Example permission matrix**

| Permission | Viewer | Editor | Admin | Owner |
|---|---|---|---|---|
| `document:read` | ✅ | ✅ | ✅ | ✅ |
| `document:write` | | ✅ | ✅ | ✅ |
| `document:delete` | | | ✅ | ✅ |
| `member:manage` | | | ✅ | ✅ |
| `org:delete` | | | | ✅ |

**Target API style**

```python
@router.delete("/orgs/{org_id}/documents/{doc_id}")
async def delete_document(
    doc: Document = Depends(load_document_in_org),
    principal: Principal = Depends(require_permission("document:delete")),
): ...
```

**One `Principal` across every identity provider**

Routes depend on a shared `Principal`, so authorization logic stays the same whichever IdP issued the token.

| Issuer | Key check | Identity | Roles source |
|---|---|---|---|
| App 1 | `iss`, `aud` | `sub` | Database |
| Keycloak | `iss`, `aud` | `sub` | `realm_access.roles` |
| Entra ID | `iss`, `aud`, `tid` | `oid` with `tid` | `roles` |
| Cognito | `iss`, `client_id`, `token_use` | `sub` | `cognito:groups` |

**Build sequence**
1. Model roles, permissions, and role assignments on tenant memberships with Alembic migrations.
2. Build `require_permission()` and a tenant-scoped resource loader.
3. Extend the Phase 8 token validator so each issuer's roles map to `Principal`.
4. Add ownership rules, so authors can edit their own documents.
5. Add an ABAC rule: confidential documents can be read only by members with clearance.
6. Prevent escalation: Admins cannot grant Owner or change their own role.
7. Reimplement one permission in OpenFGA or Casbin, and record what changed.

**Test approach:** Generate a matrix test for every role and every route, covering both allowed and denied outcomes, plus cross-tenant access attempts.

**Exit criteria**
- [ ] The role and route test matrix fully passes.
- [ ] A user's role in one tenant gives them no rights in another.
- [ ] Tokens from all configured IdPs reach the same authorization code.
- [ ] A removed member loses access within a defined and tested time.
- [ ] You can justify choosing RBAC, ABAC, or ReBAC for a given product.

---

### Phase 10: Other Authentication Methods

**Goal:** Cover what real systems add around passwords and OIDC. Most of this extends Apps 1 and 7.

| # | Topic | Build |
|---|---|---|
| 1 | **TOTP MFA** | QR enrollment with `pyotp`, hashed recovery codes, and step-up auth for sensitive actions |
| 2 | **Passkeys / WebAuthn** | Registration and login with `webauthn`, tested using Chrome's virtual authenticator |
| 3 | **Magic links** | Single-use, expiring, hashed tokens, with a local mail catcher such as Mailpit |
| 4 | **Password reset** | Secure reset that also revokes existing sessions |
| 5 | **API keys** | Prefixed keys, stored hashed, with scopes, expiry, rotation, and last-used tracking |
| 6 | **Service-to-service** | Compare client credentials and mTLS, using a local CA for the mTLS lab |
| 7 | **Concept notes** | LDAP, Kerberos, workload identity, DPoP, and RFC 8693 token exchange |

**Exit criteria**
- [ ] MFA enrollment and recovery both work, and recovery codes are single-use.
- [ ] A passkey login works, and you can explain why it resists phishing.
- [ ] A leaked API key can be revoked immediately, and the database never stores it in plaintext.

---

### Phase 11: Application Access, User Tiers, and Admin Panel

**App 8: `app8_access`**, three applications protected by one access service and managed from one admin panel.

**What this phase delivers**
- Three applications, each with its own application ID.
- A signed-in user can use an application only if they hold a grant for it.
- Without a grant, they see: **"You are not authorized to use this application. Please check with your admin."**
- Each grant sets a level: **Basic, Standard, or Premium**.
- Admins sign in to a panel to grant, change, suspend, and revoke access.

#### How it works

```
             1. Sign in                 +----------+
   +--------------------------------->  |  IdP     |
   |  <---- token for this app only --  | Keycloak |
   |                                    +----------+
+--+------+   2. Request   +---------------------------+
|  User   | -------------> | Notes / Reports / Files   |  Enforcement: validates
+---------+                | access_client             |  token, applies decision
   ^                       +-------------+-------------+
   |                                     | 3. "Can this user use this app,
   |  4. App opens at the user's tier,   |     and this feature?"
   |     or the "not authorized" page    v
   |                       +---------------------------+
   +---------------------- | Access Service            |  Decision: default deny
                           +-------------+-------------+
                                         |
+---------+   Grant, change, revoke      v
|  Admin  | --> Admin Panel -->  Postgres grants and audit log
+---------+                      Redis decision cache
```

| Standard term | In App 8 | Job |
|---|---|---|
| Policy Enforcement Point (PEP) | `access_client` inside each app | Applies the decision |
| Policy Decision Point (PDP) | Access Service | Makes the decision |
| Policy Administration Point (PAP) | Admin Panel | Manages the rules and grants |
| Policy Information Point (PIP) | Postgres | Supplies users, grants, and tiers |

#### Why this approach

| Option | Used by | Pros | Cons | Verdict |
|---|---|---|---|---|
| Block access at the IdP | Entra "Assignment required" | Simple, no code | Users see the IdP's error page, for example AADSTS50105, and you cannot show your own message | Learn it in a lab |
| Put the tier in the token | Entra app roles, Cognito groups | No extra call on each request | Changes wait until the token expires | Learn it in earlier phases |
| **Central access service with a short cache** | Dedicated policy and entitlement systems | Custom message, one admin panel, fast revocation, works with any IdP | One more service, which must stay available | **Used here** |

Entra's built-in route is often the right choice for internal company apps that need no tiers. App 8 needs a custom message and product tiers, which is why it uses a central service. Step 15 compares the two directly.

#### Application IDs

| Identifier | Example | Purpose | Can it change? |
|---|---|---|---|
| `application_id` | `3f6c...` (UUID) | Your permanent internal ID, used in grants and logs | Never, and never reused |
| `app_key` | `notes` | Readable name for code and URLs | Rarely |
| `client_id` | `notes-app` | The app's identity at each IdP | Differs by IdP and environment |
| `aud` claim | `notes-app` | Shows which app a token was issued for | Set by the IdP |

An `application_clients` table maps `(issuer, client_id)` to `application_id`, so one application can run across several IdPs and environments.

**Security rule:** The app never accepts its application ID from the browser. It comes from server configuration, and the Access Service confirms it matches the calling app.

#### Tiers and entitlements

Tiers are compared by a numeric rank, not by name: Basic 10, Standard 20, Premium 30. The gaps let you add a tier later without changing existing data.

App code checks **features**, never tier names. Changing what Premium includes is then a data change, not a code change.

| Application | Feature | Basic | Standard | Premium |
|---|---|---|---|---|
| **Notes** | Create and read notes | Up to 50 | Unlimited | Unlimited |
| | Share with teammates | | ✅ | ✅ |
| | Version history and PDF export | | | ✅ |
| **Reports** | View dashboards | ✅ | ✅ | ✅ |
| | Filter and export CSV | | ✅ | ✅ |
| | Scheduled reports | | | ✅ |
| **Files** | Storage | 100 MB | 5 GB | 50 GB |
| | Folders | | ✅ | ✅ |
| | External share links | | | ✅ |

**Three checks must all pass:** the user belongs to the tenant, holds a tier that includes the feature, and has a role that allows the action. A Premium Viewer still cannot delete a document, and a Basic Admin still cannot export a PDF.

#### Data model

| Table | Key fields | Notes |
|---|---|---|
| `applications` | `application_id`, `app_key`, `name`, `status` | Status is `active`, `maintenance`, or `retired` |
| `application_clients` | `application_id`, `issuer`, `client_id`, `environment` | Unique on issuer and client ID |
| `tiers` | `tier_id`, `application_id`, `key`, `rank` | Each app defines its own tiers |
| `features` | `feature_id`, `application_id`, `key` | For example `notes.export` |
| `tier_features` | `tier_id`, `feature_id`, `limit_value` | Stores quotas such as 50 notes |
| `user_app_access` | `tenant_id`, `user_id`, `application_id`, `tier_id`, `status`, `starts_at`, `expires_at`, `source`, `granted_by`, `reason`, `version` | Only one live grant per user, tenant, and app |
| `groups`, `group_members`, `group_app_access` | `tenant_id`, `group_id`, `application_id`, `tier_id` | Grants through a team or department |
| `tenant_app_licenses` | `tenant_id`, `application_id`, `tier_id`, `seat_limit`, `expires_at` | Optional seat limits |
| `access_requests` | `user_id`, `application_id`, `requested_tier`, `status`, `reviewed_by` | One open request per user and app |
| `admin_roles` | `user_id`, `role`, `application_id` | `application_id` scopes an App Admin |
| `access_audit_log` | `actor_id`, `action`, `target`, `before`, `after`, `reason`, `request_id`, `at` | Append-only |

Grants are never hard-deleted. The `source` field records `admin`, `group`, `scim`, or `billing`, so a payment system can set tiers later without a redesign. All tenant-owned tables use the RLS rules from Phase 8.

#### Access decision

**API:** The check follows the shape of OpenID's **AuthZEN Authorization API 1.0**, finalized in January 2026. Confirm the exact format against the spec during the build. Errors use **RFC 9457** Problem Details.

```http
POST /access/v1/evaluation
Authorization: Bearer <service token for notes-app>

{
  "subject": {"type": "user", "id": "<user-id>"},
  "resource": {"type": "application", "id": "<application-id>"},
  "action": {"name": "use"},
  "context": {"tenant_id": "<tenant-id>", "feature": "notes.export"}
}
```

```json
{
  "decision": false,
  "context": {"reason_code": "NO_APP_ACCESS", "reference_id": "a81f2c"}
}
```

**How an app uses it**

```python
@router.post("/notes/export")
async def export_notes(
    access: AppAccess = Depends(require_feature("notes.export")),
): ...
```

**Checks run in this order, and the first failure decides the result**

| # | Check | Reason code | HTTP | What the user sees |
|---|---|---|---|---|
| 1 | Valid session or token | `NOT_AUTHENTICATED` | 401 | Redirect to login |
| 2 | Token issued for this app | `WRONG_AUDIENCE` | 401 | Redirect to login for this app |
| 3 | User is active | `USER_DISABLED` | 403 | "Your account is disabled. Please contact your admin." |
| 4 | Tenant is active | `TENANT_SUSPENDED` | 403 | "Your organization's access is suspended." |
| 5 | Application is available | `APP_MAINTENANCE` | 503 | "This application is temporarily unavailable." |
| 6 | Application still exists | `APP_RETIRED` | 410 | "This application is no longer available." |
| 7 | User has a grant | `NO_APP_ACCESS` | 403 | **"You are not authorized to use this application. Please check with your admin."** |
| 8 | Grant is not suspended | `ACCESS_SUSPENDED` | 403 | "Your access is suspended. Please check with your admin." |
| 9 | Grant has started and not expired | `ACCESS_EXPIRED` | 403 | "Your access has expired. Please check with your admin." |
| 10 | Tier includes the feature | `TIER_TOO_LOW` | 403 | "This feature is not included in your Basic plan. Please check with your admin." |
| 11 | Quota not used up | `QUOTA_EXCEEDED` | 403 | "You have reached your Basic plan limit." |

**The "not authorized" page**
- It shows the message, the user's signed-in email, and a sign-out link so they can try another account.
- It offers a **Request access** button and a short reference ID for support.
- It has no redirect back to login, which prevents an endless loop.
- API clients receive `application/problem+json` with the same `reason_code`.

#### Admin Panel

The panel is a separate application with its own IdP client. It calls the Access Service API and has no direct access to grant tables, so all rules and audit logging live in one place.

**Screens**

| Screen | What you can do |
|---|---|
| Dashboard | See counts, pending requests, grants expiring soon, and recent changes |
| Users | Search users, and filter by application, tier, or status |
| User detail | See one row per app, set tier, suspend, revoke, set an expiry, and see history |
| Access matrix | View users against apps on one page, and edit tiers there |
| Applications | Manage application IDs, client IDs, status, and tier features |
| Groups | Manage members and each group's app tier |
| Access requests | Approve, reject, or change the requested tier |
| Bulk changes | Upload a CSV, preview the result, then apply it |
| Access reviews | Periodically confirm or remove existing access, including inactive users |
| Audit log | Search all changes, and look up a user's reference ID |
| Admins | Assign admin roles |

**Admin roles**

| Action | Super Admin | App Admin | Helpdesk | Auditor |
|---|---|---|---|---|
| View users and access | ✅ | Own apps | ✅ | ✅ |
| Grant, change, revoke access | ✅ | Own apps | | |
| Suspend a user's access | ✅ | Own apps | ✅ | |
| Manage applications and tiers | ✅ | | | |
| Manage admins | ✅ | | | |
| View audit log | ✅ | Own apps | | ✅ |

**Admin security**
- MFA is required on every admin sign-in, enforced by checking the token's `acr` or `amr` claim.
- Sessions time out after 15 minutes idle and 8 hours in total.
- Sensitive actions, such as managing admins or bulk changes, require recent re-authentication.
- Every change needs a reason and writes an audit record in the same transaction.
- All forms use CSRF tokens, and destructive actions need confirmation.
- The first Super Admin is created by a command-line tool, never through a public sign-up page.
- In production, the panel sits behind a VPN or private network.

#### Build sequence

1. **Keycloak clients:** Create `notes-app`, `reports-app`, `files-app`, and `admin-panel`, with audience mappers, a service client per app, and a realm export.
2. **Access Service schema:** Add the tables, migrations, seed data, and RLS policies.
3. **Decision API:** Build `/access/v1/evaluation` with default deny, ordered checks, and reason codes.
4. **Service authentication:** Apps call the service with client credentials and can only ask about their own application ID.
5. **Shared client:** Build `access_client` with `require_app_access()` and `require_feature()`.
6. **Three apps:** Build Notes, Reports, and Files with feature gates and quotas.
7. **Denied experience:** Add the "not authorized" page, Problem Details responses, and reference IDs.
8. **Admin sign-in:** Add login, MFA checks, admin roles, and the bootstrap command.
9. **Admin screens:** Build users, the user detail page, access matrix, applications, and audit log.
10. **Access requests:** Connect the Request access button to an approval queue.
11. **Groups:** Compute the effective tier across direct and group grants.
12. **Fast revocation:** Cache decisions in Redis for 30 seconds, and retire them immediately by changing a version number in the cache key. This replaced the planned pub/sub, because a lost message cannot leave a stale decision.
13. **Lifecycle:** Add expiring grants, automatic expiry, joiner, mover, and leaver handling, and the SCIM hook from Phase 7.
14. **Bulk and reviews:** Add CSV import with preview, then access reviews.
15. **Entra comparison lab:** Turn on "Assignment required", capture what an unassigned user sees, and map tiers to app roles. Sources conflict on this setting for OIDC sign-in, so record what actually happens.
16. **Optional My Apps page:** A launcher listing only the apps a user can open.
17. **Edge case suite:** Turn every edge case below into a test.

**Effective tier rules**
1. A suspended direct grant denies access, even if a group grants it.
2. Otherwise, the highest active tier from direct and group grants wins.
3. A tier cannot exceed the tenant's license for that app.
4. No active grant means no access.

#### Edge cases

Each row becomes an automated test, unless a test is marked as manual.

**Identity and sign-in**

| Case | Expected behavior |
|---|---|
| Valid IdP user who has never been seen before | Create the user with no grants, then show the "not authorized" page |
| Denied user is sent back to login | No redirect loop, because the denied page is final |
| User is denied but has another account | Sign-out on the denied page also ends the IdP session, so they can switch |
| User's email changes | Grants stay, because they follow the user ID |
| New employee reuses a former employee's email | They get a new user ID and inherit nothing |
| Same person signs in through Google and Entra | Two users unless linked, and an admin can merge them with audit |
| User deep-links to a page, then signs in | Return to that page, using only validated relative paths |
| User is disabled at the IdP but holds a live token | Denied once SCIM or back-channel logout arrives, and tokens are short-lived as a backstop |

**Application IDs and tokens**

| Case | Expected behavior |
|---|---|
| Notes token sent to Reports | Rejected on `aud` |
| Browser sends a different application ID | Ignored, because the ID comes from server configuration |
| Notes asks about a user's access to Files | Rejected by the Access Service |
| Unknown application ID | Denied and logged as a misconfiguration |
| New client added for an existing app | Existing grants still apply through `application_clients` |
| Application is retired | IDs are kept forever, and sign-in shows the retired message |
| User edits a tier in a cookie or token | Has no effect, because the tier comes from the server |

**Grants and tiers**

| Case | Expected behavior |
|---|---|
| Access revoked during a session | Blocked on the next request, in seconds and at most after the cache TTL |
| Tier upgraded during a session | New features work on the next request, without signing in again |
| Tier downgraded with data over the new limit | Existing data stays readable, and new items are blocked until under the limit. Nothing is deleted. |
| Grant starts in the future | Denied until the start time |
| Grant expires exactly now | Denied, with times taken from the database clock in UTC |
| Direct Basic and group Premium | Premium applies |
| User leaves the group | Tier falls back to any direct grant, otherwise access ends |
| Direct grant suspended, group grant active | Denied |
| User belongs to two tenants | Access is checked separately in each tenant |
| Tenant license drops from Premium to Standard | Users are capped at Standard, and original grants remain on record |
| Seat limit reached | Grant is refused with a clear message, even when two admins try at once |
| Tier deleted while users hold it | Blocked until those users are moved to another tier |
| New tier added between two others | Works without changing existing grants, thanks to rank gaps |
| New feature added | Hidden from all tiers until an admin assigns it |

**Long-running work**

| Case | Expected behavior |
|---|---|
| Revoked user has an export running | The job rechecks access before delivering results |
| Scheduled report for a revoked user | Skipped and logged |
| Revoked user holds a signed download link | Links are short-lived, and new links need a fresh check |
| Open WebSocket after revocation | Server rechecks periodically and closes the connection |
| Refresh token used after revocation | Refresh rechecks access |
| Background job runs for a user | It uses the user's current tier, not the tier when it was queued |

**Admin panel**

| Case | Expected behavior |
|---|---|
| Last Super Admin is removed or demoted | Blocked |
| Admin changes their own access | Blocked, and another admin must do it |
| Two admins edit one grant at once | The second gets a conflict message, using the `version` field |
| Double-clicked form submission | Applied once, using an idempotency key |
| Admin role removed mid-session | Next admin action is denied |
| Stale browser page after session timeout | Redirect to login, with the change not applied |
| Bulk CSV has some bad rows | Preview flags them, and applying is all-or-nothing |
| Same CSV is uploaded twice | The second upload changes nothing |
| CSV cell starts with `=` | Exported data is escaped to prevent spreadsheet formula injection |
| User submits repeated access requests | One open request per app, plus rate limits |
| Request is approved after the user was disabled | Approval fails with a clear reason |
| Request reason contains HTML or script | Escaped on display, so it cannot attack the admin |
| App Admin attempts to change another app's grant | Rejected on the server, not only hidden in the UI |

**Failures**

| Case | Expected behavior |
|---|---|
| Access Service is down | Fail closed with "temporarily unavailable", never the "not authorized" message |
| Redis is down | Fall back to the database, and accept slower requests |
| Revocation message is lost | The 30-second cache TTL still limits exposure |
| Database is down | Show a temporary error, and grant nothing |
| IdP is down | Existing sessions continue until expiry, and new sign-ins show an outage message |
| Audit write fails | The whole change rolls back |
| Clock differs between services | Expiry is judged only by the Access Service |

**Privacy and compliance**

| Case | Expected behavior |
|---|---|
| Denied page reveals other applications | It names only the app being opened |
| Back button after sign-out | Protected pages use `Cache-Control: no-store` |
| User requests erasure | Personal data is removed, and audit rows keep an anonymous ID |
| Attacker floods denied requests | Denials are rate-limited, and repeated ones are grouped in the logs |
| Support needs to find a denial | The reference ID finds the exact decision in the audit log |

**Decisions for Phase 11**
- **Scope:** Tiers are set per application, so a user can be Premium in Notes and Basic in Reports.
- **Who sets tiers:** Admins only. Payments are out of scope, and `source = billing` leaves room for them.
- **Revocation:** Up to 30 seconds is the worst case, and usually it is immediate through version numbers. High-risk features can skip the cache.
- **Failure mode:** Every app fails closed by default.

**Exit criteria**
- [ ] A signed-in user with no grant sees your exact "not authorized" message in all three apps.
- [ ] A user with a grant reaches the app at the correct tier.
- [ ] Basic, Standard, and Premium each unlock the correct features and quotas.
- [ ] A token for one app is rejected by the other two.
- [ ] A revoked user is locked out within 30 seconds without signing out.
- [ ] A tier change takes effect without a new sign-in.
- [ ] You can sign in to the admin panel with MFA, then grant, change, suspend, and revoke access.
- [ ] Every admin action appears in the audit log with a reason.
- [ ] Each admin role can do only what its row allows.
- [ ] An Access Service outage shows "temporarily unavailable" and grants nothing.
- [ ] Every edge case has a passing test or a written reason for manual testing.

---

### Phase 12: Production Hardening

**Goal:** Finish Apps 7 and 8 to a standard you could defend in a design review.

**Application security**
- [ ] Argon2id parameters tuned on target hardware, with breached-password checks.
- [x] Per-account and per-IP rate limits on login, reset, and token routes.
- [x] Progressive login throttling that does not let attackers lock out users.
- [x] Uniform login and reset responses to prevent user enumeration.
- [x] Strict CORS allowlist, with no wildcards alongside credentials.
- [x] CSRF protection on all cookie-authenticated writes.
- [x] Security headers: HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`.
- [x] Open-redirect-safe redirect handling.
- [x] Input validation and request size limits.

**Token and session lifecycle**
- [x] Documented lifetimes for each token type.
- [x] A user-facing list of active sessions with remote logout.
- [x] Full revocation on password change or suspected compromise.
- [x] Scheduled signing key rotation, plus an emergency procedure.

**Federation and tenancy**
- [ ] SAML certificate expiry monitoring, with a tested rotation procedure.
- [ ] Per-tenant IdP configuration stored encrypted and changes audited.
- [x] Verified domains required before a tenant can enforce SSO.
- [x] A tested break-glass path when a customer's IdP is down.
- [x] Per-tenant rate limits and tenant ID on all logs and audit events.
- [x] A test that fails if any tenant-owned table lacks an RLS policy.

**Access Service and admin panel**
- [x] Access Service runs with more than one instance, and its response times are measured.
- [ ] Alerts on unusual grant volume, new Super Admins, and failed admin sign-ins.
- [ ] Admin panel reachable only from a private network.
- [x] Audit log protected from edits, with a retention policy.
- [ ] Scheduled access reviews, with a record of each outcome.
- [ ] Revocation time measured under load against the 30-second target.

**Secrets and infrastructure**
- [ ] Secrets injected at runtime, with AWS Secrets Manager or Azure Key Vault as the cloud pattern.
- [x] Docker image as a non-root user, multi-stage, with health checks.
- [x] TLS via a Caddy reverse proxy, including correct proxy header trust.
- [x] Least-privilege database users.
- [x] Backup and restore tested.

**Observability and audit**
- [x] Structured logs with request IDs, and **no tokens, passwords, or secrets in logs**.
- [x] Append-only audit trail for logins, failures, role changes, and key events.
- [ ] Metrics and alerts for failed login spikes and token reuse.

**Delivery and verification**
- [ ] GitHub Actions CI: tests, `ruff`, `bandit`, `pip-audit`, and image scan.
- [x] Self-assessment against OWASP ASVS Level 2 and the API Security Top 10.
- [x] Threat model of Apps 7 and 8 using STRIDE.
- [ ] Load test of login and token validation.
- [x] Incident runbooks for a leaked signing key, a compromised admin, and an IdP outage.

**Optional stretch:** Deploy to AWS ECS or Azure Container Apps.

**Exit criteria**
- [ ] A fresh machine can run the stack from the README alone.
- [ ] All checks above are completed or have a written reason for being skipped.
- [ ] You can run through the leaked-signing-key runbook end to end.
- [ ] You can present the architecture, threat model, and tradeoffs of Apps 7 and 8 in 15 minutes.

---

## 5. Choosing a Solution

Use this as a starting point. You will refine it with your own notes after Phase 7.

| Situation | Starting choice |
|---|---|
| Employees and Microsoft 365 organizations | Microsoft Entra ID |
| Customer app on AWS | Amazon Cognito |
| Customer app on Azure | Microsoft Entra External ID |
| Self-hosting, data control, or avoiding vendor lock-in | Keycloak |
| Small first-party API, no SSO needed | Your own JWT or sessions, using proven libraries |
| Browser web app | Server-side session or BFF |
| Service-to-service | Client credentials or workload identity, with mTLS where needed |
| Selling to enterprises | OIDC plus SAML and SCIM support |
| Consumer app wanting easy sign-up | Google plus one or two providers your users already have |
| Small team needing enterprise SSO quickly | A hosted platform or a broker such as Keycloak |
| Multi-tenant SaaS on Postgres | Shared tables with `tenant_id` and row-level security |
| Customer with strict data residency rules | A database per tenant |
| Internal company app, simple yes or no access | Entra "Assignment required" with app roles |
| Several apps with one custom access panel | A central access service |
| Paid product plans | Entitlements checked by feature, never by plan name |

---

## 6. Risks and Costs

| Risk | Handling |
|---|---|
| Unexpected AWS charges | Budget alert first, Essentials only, no SMS, and full teardown |
| Azure portal or Microsoft licensing changes | Check current Microsoft docs at the start of Phase 4 |
| Cognito prices or feature plans change | Check the AWS pricing page at the start of Phase 5 |
| Provider UIs differ from any guide | Follow concepts, and use current official docs for navigation |
| Keycloak environment variable names differ by version | Pin one version and follow that version's docs. `KC_BOOTSTRAP_ADMIN_*` is the newer naming. |
| Too much scope at once | Finish each phase's exit criteria before moving on. Optional steps can be skipped. |
| Committing a secret | `.env` is git-ignored from Phase 0, and CI adds secret scanning in Phase 12 |
| Access Service becomes a single point of failure | Short caching, fast decisions, health checks, and more than one instance in Phase 12 |
| Admin panel account is compromised | MFA, re-authentication, narrow admin roles, private network, and alerts |
| Cached decisions delay revocation | Version numbers retire them, the 30-second TTL limits them, and high-risk features skip the cache |
| Phase 11 grows too large | Steps 14 and 16, groups, and seat limits can move to a later pass without affecting the core flow |
| `python3-saml` or `xmlsec` install trouble | Build App 6's SAML app in a Linux container, and pin `xmlsec` and `lxml` together |
| Entra ID licensing for SAML | Reports suggest basic SAML works on the free tier, but sources conflict for custom apps. Check Microsoft's feature comparison before Phase 7, and rely on Keycloak if it is blocked. |
| Entra ID provisioning needs a paid license | SCIM is tested with direct API calls, so no license is needed |
| Okta free accounts may not offer SAML | Reports conflict. Okta stays optional, and the free plan has a limit of 10 active users. |
| Apple login requires a paid membership | Apple stays concept-only unless you already have one |
| Keycloak organization claim format is unconfirmed | Confirm it on the pinned version in Phase 8 |
| RLS gives false confidence | Run the proof test and pool test, and connect as the real application role |

---

## 7. How We Will Work Through This

1. You approve or change this plan.
2. For each phase, I explain the concepts and we confirm scope.
3. We build the app one step at a time, and you run each step yourself.
4. You work through the exit criteria, and I quiz you on anything shaky.
5. We tick off the phase here and move on.

---

## 8. References

**Standards**
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [RFC 6749: OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7519: JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9068: JWT Profile for Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 7644: SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644)
- [RFC 9457: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
- [OpenID AuthZEN Authorization API 1.0 approval](https://openid.net/authorization-api-1-0-final-specification-approved/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [SAML 2.0 specifications](https://docs.oasis-open.org/security/saml/v2.0/)

**Security**
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)

**Product docs**
- [FastAPI OAuth2 with JWT tutorial](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
- [Keycloak documentation](https://www.keycloak.org/documentation)
- [Keycloak Organizations announcement](https://www.keycloak.org/2024/06/announcement-keycloak-organizations)
- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [python3-saml](https://github.com/SAML-Toolkits/python3-saml)
- [Okta organization defaults and plan limits](https://developer.okta.com/docs/reference/org-defaults/)
- [Microsoft identity platform documentation](https://learn.microsoft.com/entra/identity-platform/)
- [Restrict a Microsoft Entra app to a set of users](https://learn.microsoft.com/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users)
- [Azure AD B2C FAQ](https://learn.microsoft.com/azure/active-directory-b2c/faq)
- [Amazon Cognito feature plans](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-sign-in-feature-plans.html)
- [Amazon Cognito pricing](https://aws.amazon.com/cognito/pricing/)
