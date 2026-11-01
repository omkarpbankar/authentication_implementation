# Authentication Journey

A hands-on course in authentication and authorization, built with FastAPI. It goes from HTTP Basic through to a multi-tenant platform with SSO, row-level security, and an admin panel.

**Start here:** [journey/README.md](journey/README.md)

## What is inside

| Folder | Purpose |
|---|---|
| [journey/](journey/) | Lessons and small tests, one per phase |
| [apps/](apps/) | The applications |
| [tests/](tests/) | Automated tests |
| [scripts/](scripts/) | Setup scripts, and live checks that run the real servers |
| [docs/](docs/) | Your notes, design documents, the threat model, and incident runbooks |
| [deploy/](deploy/) | Production-style container, TLS proxy, and alert rules |
| [infra/](infra/) | AWS template for Phase 5 |

## The apps

| Phase | App | Topic |
|---|---|---|
| 1 | `phase1_fundamentals` | Basic auth, sessions, and a CSRF lab |
| 2, 10 | `app1_jwt` | JWT, MFA, passkeys, magic links, and API keys |
| 3 | `app2_oidc` | OAuth 2 and OpenID Connect with Keycloak |
| 4 | `app3_entra` | Microsoft Entra ID |
| 5 | `app4_cognito` | Amazon Cognito |
| 6 | `app5_social` | Google, Microsoft, and GitHub login |
| 7 | `app6_sso` | SSO, SAML, and SCIM |
| 8, 9 | `app7_platform` | Tenants, row-level security, and permissions |
| 10 | `mtls_lab` | Mutual TLS |
| 11 | `app8_access` | Application access, tiers, and an admin panel |

## Design and security documents

| Document | Contents |
|---|---|
| [High-Level Design](docs/design/HLD.md) | Goals, architecture, key flows, deployment, and trade-offs |
| [Low-Level Design](docs/design/LLD.md) | Data model, decision algorithm, APIs, configuration, and how to extend |
| [Threat model](docs/security/threat-model.md) | STRIDE analysis of Apps 7 and 8 |
| [Security self-assessment](docs/security/asvs-checklist.md) | Mapping to OWASP ASVS and the API Security Top 10 |
| [Token lifetimes](docs/security/token-lifetimes.md) | Every lifetime and why |
| [Runbooks](docs/runbooks/) | Leaked signing key, compromised admin, and identity provider outage |

## Set up once

You need Docker and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync
uv run python scripts/bootstrap_env.py
docker compose up -d --wait
uv run python scripts/reset_realm.py
uv run python scripts/setup_platform_db.py
uv run python scripts/setup_access_db.py
```

## Check that everything works

```powershell
uv run pytest
uv run ruff check .
uv run python scripts/live_phase11.py
```

Some ports are shared between phases (8011, 8012, 8013, and 8443), so run one phase's servers at a time. The live-check scripts handle this for you.

Practice accounts and passwords in this repository are public values for local use only. Never reuse them anywhere real.
