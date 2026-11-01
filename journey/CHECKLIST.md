# Build Checklist

Tracks what has been built and how it was verified. Ticks here mean the code exists and was checked. Your own learning is tracked separately in the [progress table](README.md).

**Verification levels**

- **Tests:** Automated tests pass.
- **Live:** Ran for real against local services.
- **Needs your account:** Code and tests exist, but it has not run against the real cloud provider.

| Phase | Build | Verification | Done |
|---|---|---|---|
| 0 | Workspace setup | Live | [x] |
| 1 | Fundamentals exercises and CSRF lab | Tests, live, real browser | [x] |
| 2 | App 1: JWT | Tests, live | [x] |
| 3 | App 2: OAuth 2 and OIDC with Keycloak | Tests, live against Keycloak | [x] |
| 4 | App 3: Entra ID | Tests against a simulated provider. **Needs your account** | [x] |
| 5 | App 4: Cognito | Tests against a simulated provider, template validated. **Needs your account** | [x] |
| 6 | App 5: Third-party login | Tests, live against Keycloak. Google, Microsoft, GitHub **need your accounts** | [x] |
| 7 | App 6: SSO, SAML, SCIM | Tests, SAML attack lab, live SSO across OIDC and SAML. Entra as IdP **needs your account** | [x] |
| 8 | App 7: Tenants and row-level security | Tests on real Postgres, live with Keycloak | [x] |
| 9 | App 7: Permissions | Full role and route matrix on real Postgres, live with Keycloak | [x] |
| 10 | MFA, magic links, reset, API keys, mTLS, passkeys | Tests, live with real email and real TLS. Passkeys tested with a software authenticator, **try the demo page with your device** | [x] |
| 11 | App 8: App access and admin panel | Tests on real Postgres, full live flow with real MFA and SSO across all apps | [x] |
| 12 | Production hardening | Tests, live drill, outage, backup, TLS, and load checks. Gaps listed below | [x] |

## Latest full verification

| Check | Result |
|---|---|
| Automated tests | See the final report for the latest count |
| SAML attack lab | 19 passed, in the container |
| Live checks | Phases 2, 3, 6, 7, 8, 10, 11, and 12 |
| Dependency audit | No known vulnerabilities |
| Security lint | No medium or high findings |

## Known gaps

These are recorded so nothing is hidden. Details are in [the security self-assessment](../docs/security/asvs-checklist.md).

- There is no breached-password check.
- Secrets use `.env` and practice defaults, not a secret manager.
- The GitHub Actions workflow is written, but has never run, as nothing has been pushed.
- Alert rules are examples, and nothing delivers them.
- Revocation speed was measured on a quiet system, not under load.
- Login was not load-tested. Only access decisions were.
- Sign-in inside the production containers needs a real Keycloak hostname. Those containers were tested for TLS, health, non-root use, and failover only.
- When an instance dies, 1 request in 24 still got a 502 during failover testing.
- Admin panel network restriction is documented, not enforced, in this local setup.
- SAML certificate expiry is not monitored.

## Steps only you can do

These need your own accounts or passwords, which Claude must not create or enter.

- [ ] Edit `REDIS_URL` in `.env` to use port 6380.
- [ ] Sign in to the Keycloak admin console.
- [ ] Phase 3: Create a GitHub OAuth app, then add GitHub as a Keycloak identity provider.
- [ ] Phase 4: Follow [App 3 setup](../apps/app3_entra/SETUP.md) with your Azure tenant.
- [ ] Phase 6: Add client IDs by following [App 5 setup](../apps/app5_social/SETUP.md).
- [ ] Phase 7: Optionally connect Entra ID, as described in the [App 6 README](../apps/app6_sso/README.md).
- [ ] Phase 5: Fix your AWS credentials, then follow [App 4 setup](../apps/app4_cognito/SETUP.md). The current credentials on this machine are invalid.
