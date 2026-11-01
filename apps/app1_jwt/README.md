# App 1: JWT Authentication

First-party login with short-lived JWT access tokens and rotating refresh tokens. The lesson is [Phase 2](../../journey/phase-02-jwt.md).

| File | Purpose |
|---|---|
| `manual_jwt.py` | A JWT built by hand with the standard library |
| `keys.py` | RSA signing keys, JWKS, rotation, and retirement |
| `tokens.py` | Creating and validating tokens |
| `store.py` | Users, refresh tokens, and the denylist in Redis |
| `main.py` | The API, on port 8001 |
| `verifier_service.py` | A second service that holds no secrets, on port 8011 |
| `rotate_keys.py` | Adds a new signing key |

```powershell
docker compose up -d --wait
uv run uvicorn apps.app1_jwt.main:app --port 8001
```

Interactive docs are at http://localhost:8001/docs.

Run the tests with `uv run pytest tests/app1_jwt -v`, and the full live flow with `uv run python scripts/live_phase2.py`.

Keys are stored in `.keys/`, which Git ignores. Users are stored in Redis to keep this app focused on tokens. App 7 uses a real database.
