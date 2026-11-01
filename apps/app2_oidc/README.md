# App 2: OAuth 2 and OpenID Connect

A web app, an API, a worker, and a CLI, all using the local Keycloak. The lesson is [Phase 3](../../journey/phase-03-oauth-oidc.md).

| File | Port | Purpose |
|---|---|---|
| `manual_flow.py` | 8002 | Authorization Code + PKCE written by hand, with server-side tokens |
| `library_flow.py` | 8012 | The same login using Authlib |
| `api.py` | 8022 | A protected API with audience and role checks |
| `worker.py` | | Client Credentials, for services with no user |
| `device_cli.py` | | Device flow, for programs with no browser |
| `oidc.py` | | Discovery, JWKS caching, and token validation |

Set up Keycloak once with `uv run python scripts/reset_realm.py`. Practice accounts are `asha` (reader and writer) and `ravi` (reader), both with the password `correct-horse-battery`.

```powershell
uv run uvicorn apps.app2_oidc.manual_flow:app --port 8002
```

Then open http://localhost:8002.

Run the tests with `uv run pytest tests/app2_oidc -v`, and the live flow with `uv run python scripts/live_phase3.py`.
