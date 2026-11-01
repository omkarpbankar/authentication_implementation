# Security Self-Assessment

Written for: reviewers checking this project against common standards.

This maps the project to the themes of **OWASP ASVS Level 2** and the **OWASP API Security Top 10**. It is a self-assessment and not a certification, and the themes are paraphrased. Check the current published standards for exact requirement numbers.

## ASVS themes

| Theme | Status | Evidence |
|---|---|---|
| Password storage | Met | Argon2id through pwdlib |
| Password policy | Partial | Minimum length is enforced, and breached-password checks are not built |
| MFA | Met | TOTP, recovery codes, step-up, required for admins |
| Credential recovery | Met | Single-use, expiring, hashed tokens, and all sessions end on reset |
| Session management | Met | Random IDs, new ID at login, server-side revocation, idle and total limits |
| Cookies | Met for local use | `HttpOnly`, `SameSite`. `Secure` needs HTTPS, so set it in production |
| Access control | Met | Default deny, server-side checks, role and route test matrix |
| Multi-tenancy | Met | RLS, composite keys, proof tests |
| Input validation | Met | Pydantic models, size limits |
| Output encoding | Met | Jinja autoescape, `escape()`, CSV formula protection |
| Cryptography | Met | Standard libraries only, RS256, no hand-written crypto in production paths |
| Secrets | Partial | Git-ignored `.env`. A real secret manager is a deployment step |
| Logging | Met | Structured, redacted, append-only audit log |
| API security | Met | Audience checks, scopes, rate limits |
| Configuration | Partial | Hardened container and TLS proxy are verified. `Secure` cookies and HSTS need enabling per deployment |
| Dependencies | Met | `pip-audit` clean, and versions locked |

## API Security Top 10 themes

| Risk | Status | Control |
|---|---|---|
| Broken object level authorization | Met | Tenant-scoped loading, RLS |
| Broken authentication | Met | Token validation, rate limits, MFA |
| Broken object property level authorization | Met | Explicit response models |
| Unrestricted resource consumption | Partial | Rate limits and size limits exist, but not on every route |
| Broken function level authorization | Met | Permission checks on every route, enforced by a matrix test |
| Unrestricted access to sensitive business flows | Partial | Limits on login, email, and requests |
| Server-side request forgery | Met | Outbound calls go only to configured URLs |
| Security misconfiguration | Partial | Headers and strict CORS are in place. Production values must be set |
| Improper inventory management | Met | Application catalog, route count test |
| Unsafe consumption of APIs | Met | IdP tokens and provider responses are validated |

## Gaps to close before real production use

1. Add a breached-password check.
2. Use a real secret manager, instead of `.env` and practice defaults.
3. Serve everything over HTTPS, set `Secure` cookies, and enable HSTS on the apps.
4. Run the apps with real Keycloak hostnames, which the local container test does not cover.
5. Review the container image's unpatched operating-system findings. CI ignores findings with no fix available, so check the Trivy report from time to time, and rebuild the image when Debian publishes patches.
6. Add alert delivery, since `deploy/alerts.yml` holds example rules only.
7. Commission an independent penetration test.
