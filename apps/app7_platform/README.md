# App 7: Multi-Tenant Platform

A document platform with tenant isolation, row-level security, and permissions. The lessons are [Phase 8](../../journey/phase-08-tenants-rls.md) and [Phase 9](../../journey/phase-09-authorization.md).

| File | Purpose |
|---|---|
| `migrations/versions/` | Tables, row-level security policies, and roles |
| `database.py` | Sets the tenant for each transaction |
| `identity.py` | Turns every provider's token into one `Identity` |
| `auth.py` | Tenant tokens, the `Principal`, and `require_permission()` |
| `queries.py` | Every SQL statement |
| `main.py` | The API, on port 8008 |
| `casbin_comparison.py` | The same rules expressed in a policy engine |

## Run it

```powershell
docker compose up -d --wait
uv run python scripts/setup_platform_db.py
uv run uvicorn apps.app7_platform.main:app --port 8008
```

Interactive docs are at http://localhost:8008/docs.

| Check | Command |
|---|---|
| Tests against real Postgres | `uv run pytest tests/app7_platform -v` |
| Live flow | `uv run python scripts/live_phase8.py` |

## How a request is handled

1. A client swaps a provider token for a short-lived tenant token at `POST /session`.
2. Each request sends that token to a `/t/{tenant}/...` route.
3. `tenant_db` checks the signature, that the token matches the URL, that the tenant is active, and that the user is still a member.
4. It opens a transaction with `app.tenant_id` set, so row-level security applies to everything after that.
5. `require_permission()` checks what the user's role allows.

## Database roles

| Role | Used by | Can bypass RLS? |
|---|---|---|
| `platform_owner` | Migrations | No, as `FORCE` applies to it |
| `platform_app` | The running app | No |
| `platform_support` | Audited support access, with a live grant | No |

## Lessons from building this

- **Keycloak's organization claim** is a list of aliases on version 26.8, such as `["acme"]`.
- **`NULLIF` matters.** After a transaction ends, the setting reads as an empty string, and casting that to `uuid` raises an error.
- **Commit timing matters.** `tenant_db` uses `scope="function"`, so the commit happens before the response is sent, and a client never reads stale data.
