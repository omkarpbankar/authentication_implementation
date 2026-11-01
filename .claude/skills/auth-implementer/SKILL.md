---
name: auth-implementer
description: Conventions for building this repo's FastAPI authentication apps. Use this whenever writing, changing, testing, or reviewing code under apps/, tests/, docker-compose.yml, or anything involving login, sessions, tokens, cookies, OAuth, OIDC, SAML, permissions, tenants, or secrets in this project.
---

# Auth Implementer

Build the phase described in `.claude/PLAN.md`, in its build order. This is a learning repo, so code should be small and readable while still following real security practice.

## Stack

- Python 3.11 in the existing `.venv`, managed by `uv`. Add packages with `uv add`, or `uv add --dev` for test tools.
- FastAPI, PyJWT, pwdlib with Argon2, Authlib, SQLAlchemy, and Redis, as listed in the plan.
- Docker Compose runs Postgres, Redis, and Keycloak on `127.0.0.1` only.

## Layout

- Each app lives in `apps/<app_name>/`, and its tests in `tests/<app_name>/`.
- Use the ports listed in the plan, so several apps can run at once.
- Read configuration from environment variables through `pydantic-settings`.
- Each app has a `README.md` covering how to run it and what it demonstrates.

## Security defaults

These are chosen to fail safe, so a mistake denies access instead of granting it.

- Passwords are hashed with Argon2id, never stored or logged in plain text.
- Compare secrets with `secrets.compare_digest`, because `==` can leak information through timing.
- Generate tokens and session IDs with the `secrets` module.
- Session cookies are `HttpOnly` and `SameSite`, and `Secure` everywhere except local HTTP.
- Create a new session ID at login, which prevents session fixation.
- Return the same login error for a wrong email and a wrong password.
- JWT validation uses a fixed algorithm list and checks `iss`, `aud`, and `exp`.
- Authorization is default deny, and is enforced on the server.
- Never put tokens, passwords, or secrets in logs or error messages.
- Keep real secrets in `.env`, which is git-ignored. Do not read or print it. Add new names to `.env.example` with placeholder values.

## Testing

Run `uv run pytest` and `uv run ruff check .` before calling anything done. Each phase also has a live check in `scripts/live_phase*.py`, which runs the real servers against real services. Run it too, because every serious bug in this repo got past unit tests and was found this way.

Every security feature needs a failure test as well as a success test: expired, forged, missing, wrong audience, wrong role, and another tenant's data. Prove what gets rejected.

Unit tests cannot prove browser behavior such as `SameSite`. For those, verify in a real browser, and say plainly if that check was not done.

Labs that demonstrate an attack stay on the learner's own local machine, and always include the fix.

## Teaching in the code

Add a comment where a line exists for a security reason, since that is what the learner is here to see. Do not narrate ordinary Python. Each phase's lesson in `journey/` should point to the matching code.

## Finishing a phase

1. Run the tests and linter, and run the app itself.
2. Tick the phase's exit criteria in `.claude/PLAN.md` only when they are really met. Criteria about the learner's own understanding stay open until they pass the test.
3. Update the phase lesson with exact run commands.
4. Report anything skipped or unverified.

Commit only when the user asks.
