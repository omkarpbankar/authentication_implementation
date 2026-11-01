# Phase 11: Application Access, User Tiers, and Admin Panel

**Goal:** Decide who can use each application, and at what level.
**You will build:** App 8, with Notes, Reports, and Files, an Access Service, and an admin panel.

## The big idea

Think of a gym chain. Your ID proves who you are, but that alone does not get you in. Reception checks your membership: which branches you can use, and whether you are Basic, Standard, or Premium.

- **Authentication:** The user proves who they are.
- **Application access:** Do they hold a grant for this application?
- **Tier:** Which features does that grant include?

With no grant, the user sees: **"You are not authorized to use this application. Please check with your admin."**

## Learn in this order

1. **Application ID.** A permanent ID that is never reused, and never accepted from the browser.
2. **Four parts of access control.** The admin panel sets rules, the Access Service decides, each app enforces, and Postgres holds the data.
3. **Default deny.** No grant means no access.
4. **Tiers vs roles.** A tier says what the product includes. A role says what you may do.
5. **Feature checks.** Check `notes.export`, not "is Premium".
6. **Fast revocation.** Keep tiers in the database, and use a short cache.
7. **Failing safely.** An outage must not grant access, or wrongly tell someone they are unauthorized.
8. **Admin safety.** MFA, narrow roles, audit logs, and no self-service power.

## What you will build

Build the Access Service, a shared enforcement library, three apps with feature gates, the "not authorized" page, and an admin panel for granting and revoking access. Then turn each edge case into a test.

## Run it

The code is in [apps/app8_access/](../apps/app8_access/). Each command runs in its own terminal.

```powershell
uv run python scripts/reset_realm.py
uv run python scripts/setup_access_db.py
uv run uvicorn apps.app8_access.access_service.main:app --port 8010
uv run uvicorn apps.app8_access.admin_panel.main:app --port 8011
uv run uvicorn apps.app8_access.notes_app.main:app --port 8012
uv run uvicorn apps.app8_access.reports_app.main:app --port 8013
uv run uvicorn apps.app8_access.files_app.main:app --port 8014
```

**Try it yourself:**

1. Open http://localhost:8012 and sign in as `vik`, with the password `correct-horse-battery`. You see the "not authorized" message.
2. Click **Request access**.
3. In a private window, open the same address and sign in as `meera`, using the same password. This account needs a six-digit code, which this command prints: `uv run python -c "import base64, pyotp; print(pyotp.TOTP(base64.b32encode(b'course-admin-practice-totp-secret').decode()).now())"`
4. Make this account a Super Admin: `uv run python -m apps.app8_access.access_service.bootstrap_admin meera@acme.example acme`
5. Open http://localhost:8011, sign in as `meera`, approve the request, and try changing the tier. A code works only once, so wait 30 seconds for a new one if it is refused.
6. Refresh Notes as `vik`, and watch access change with no new sign-in.

Or watch the whole flow run on its own, with `uv run python scripts/live_phase11.py`.

**Learned while building:**

- Tests found a real leak: the shared `users` table let an admin in one tenant list every tenant's people. `tenant_users` with row-level security fixed it.
- Keycloak leaves the `amr` claim empty until each login step has a reference and a maximum age. See `scripts/configure_amr.py`.
- Revocation took 0.09 seconds in the live check, against a 30-second limit.

## Small test

Pass mark: 4 of 5.

**1. A user signs in correctly but has no grant for Notes. What happens?**

<details><summary>Answer</summary>

Authentication succeeds, but access is denied. They see the "not authorized" page, with a 403 status.

</details>

**2. Why isn't the tier stored in the token?**

<details><summary>Answer</summary>

A token keeps its value until it expires. In the database, a tier change takes effect within seconds.

</details>

**3. Why check `notes.export` rather than "is the user Premium"?**

<details><summary>Answer</summary>

Tiers change. Checking features lets you change what Premium includes by updating data, with no code change.

</details>

**4. A Premium Viewer tries to delete a document. What happens, and why?**

<details><summary>Answer</summary>

It is denied. The tier says what the product includes, but the Viewer role still does not allow deleting. All checks must pass.

</details>

**5. The Access Service is down. What should users see?**

<details><summary>Answer</summary>

A "temporarily unavailable" message. Access must not be granted, and "not authorized" would be misleading.

</details>
