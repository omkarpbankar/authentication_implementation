# Threat Model: Apps 7 and 8

Written for: engineers reviewing this system's design. Method: STRIDE.

## What we are protecting

| Asset | Why it matters |
|---|---|
| Customer documents | Their exposure is the worst outcome for a multi-tenant product |
| Grants and tiers | Control who can use which application |
| Signing keys | Anyone holding one can pose as any user |
| Admin accounts | Can change everyone's access |
| Audit log | The record used to investigate everything else |

## Trust boundaries

```
Browser  ──TLS──▶  Proxy  ──▶  Apps  ──service token──▶  Access Service  ──▶  Postgres (RLS)
                                │                              │
                                └───────────▶  Redis  ◀────────┘
Keycloak or another IdP issues tokens that every service verifies independently.
```

## Threats

| Type | Threat | Controls | Verified by |
|---|---|---|---|
| **Spoofing** | Forged or altered token | Fixed algorithm list, signature, `iss`, `aud`, `exp` checks | `test_attacks.py` |
| Spoofing | Token for one app used on another | Audience check per app | `test_apps.py` |
| Spoofing | Phished password | MFA for admins, passkeys available | `test_phase10.py`, live MFA check |
| Spoofing | Forged SAML assertion | Strict mode, signature, audience, replay store | SAML attack lab |
| Spoofing | One app posing as another to the Access Service | Service tokens, and each app may only ask about itself | `test_service.py` |
| **Tampering** | User edits their tier | The tier lives only on the server | `test_apps.py` |
| Tampering | Writing into another tenant | RLS `WITH CHECK`, composite foreign keys | `test_rls.py` |
| Tampering | Audit log changed to hide activity | The app role has no update or delete rights | `test_rls.py`, `test_service.py` |
| **Repudiation** | Admin denies a change | Audit row with actor, before, after, and reason, written in the same transaction | `test_service.py` |
| **Information disclosure** | Reading another tenant's data | RLS as a second layer behind application checks | `test_rls.py` |
| Information disclosure | Admin listing another tenant's users | `tenant_users` with RLS | `test_service.py` |
| Information disclosure | Tenant context leaking across pooled connections | Transaction-local settings | Pool and concurrency tests |
| Information disclosure | Secrets in logs | Redaction, and paths logged without query strings | `test_hardening.py` |
| Information disclosure | Account discovery through errors | Identical replies | Enumeration tests |
| **Denial of service** | Password guessing or flooding | Rate limits that reset on their own, with no hard lockout | `test_phase12.py`, live check |
| Denial of service | One tenant exhausting capacity | Per-tenant limits | `test_tenancy.py` |
| Denial of service | Access Service outage | Several instances, proxy retries, apps fail closed | Live failover and outage checks |
| Denial of service | Huge request bodies | Size limit | `test_hardening.py` |
| **Elevation of privilege** | Admin promoting themselves | Self-change blocked, role ranks, server-side checks | `test_permissions.py`, `test_service.py` |
| Elevation of privilege | App Admin reaching another app | Scope check on every action | `test_service.py` |
| Elevation of privilege | Changing another tenant's document by ID | Tenant scope, with the same 404 for missing and forbidden | `test_tenancy.py` |
| Elevation of privilege | Query that bypasses RLS | App role lacks `BYPASSRLS` and owns no tables, with `FORCE` enabled | `test_rls.py` |

## Accepted risks

| Risk | Why it is accepted | What would change this |
|---|---|---|
| A revoked user may keep access for up to 30 seconds if Redis fails | The cache lifetime limits the exposure, and normal revocation takes under a second | Skip the cache for high-risk features |
| Rate limits stop working if Redis is down | Blocking all sign-ins would be worse | Add limits at the proxy |
| A fixed rate window allows a short burst at each boundary | Simple, and good enough to slow guessing | Move to a sliding window |
| Practice passwords exist in this repository | They are local-only public values | Real secrets must come from a secret manager |
| One instance handles about 110 decisions a second | Short caching greatly reduces real traffic | Add instances |

## Not covered

- A compromised identity provider, because every token is trusted once it is signed.
- A compromised host, where the attacker holds the signing keys.
- Formal penetration testing. This model is a design review, not an audit.
