# Phase 8: Tenant ID and Row-Level Security

**Goal:** Serve many customers from one app without mixing their data.
**You will build:** App 7, the tenant model and database isolation.

## The big idea

A SaaS app is like an apartment building. Everyone shares the structure, but each household has private rooms. A **tenant** is one household, or one customer organization.

If a single query forgets to filter by tenant, one customer can see another's data. That is among the worst bugs a SaaS product can have, so we add a second layer. **Row-Level Security** makes the database itself enforce the rule, like a lock on each apartment door as well as a guard in the lobby.

## Learn in this order

1. **Two meanings of tenant ID.** The provider's ID, such as Entra's `tid`, and your own `tenant_id`. Map the first to the second.
2. **Users and memberships.** One user can belong to several tenants.
3. **Isolation models.** Shared tables, a schema per tenant, or a database per tenant.
4. **Tenant resolution.** A client-supplied tenant ID always needs a membership check.
5. **RLS rules.** Enable and force RLS, and connect with a role that cannot bypass it.
6. **Connection pools.** Set the tenant per transaction, so it cannot leak to the next request.
7. **Beyond the database.** Caches, files, background jobs, and logs need tenant scoping too.

## What you will build

Create the tenant schema, map each provider's identifier to your own, add RLS policies, and then write a deliberately unfiltered query to prove Postgres still blocks other tenants' rows.

## Run it

The code is in [apps/app7_platform/](../apps/app7_platform/), and the policies are in `migrations/versions/0002_row_level_security.py`.

```powershell
uv run python scripts/setup_platform_db.py
uv run uvicorn apps.app7_platform.main:app --port 8008
uv run pytest tests/app7_platform/test_rls.py -v
uv run python scripts/live_phase8.py
```

**Read this first:** `tests/app7_platform/test_rls.py`. Those tests skip the app, and connect to Postgres directly as the app's real role. They show what happens when a query forgets its tenant filter.

**Learned while building:** `NULLIF` is essential in the policy. After a transaction ends, the setting reads as an empty string rather than nothing, and casting that to a UUID raises an error.

## Small test

Pass mark: 4 of 5.

**1. What is the difference between Entra's `tid` and your app's `tenant_id`?**

<details><summary>Answer</summary>

`tid` identifies a customer's Microsoft directory. `tenant_id` is your own internal ID. You map one to the other, so your app works with any provider.

</details>

**2. A request includes the header `X-Tenant-ID: acme`. Can you trust it?**

<details><summary>Answer</summary>

No. Clients control their headers. You must confirm that the signed-in user is a member of that tenant.

</details>

**3. If application code already filters by tenant, why add RLS?**

<details><summary>Answer</summary>

As a second layer. If one query misses the filter, the database still blocks other tenants' rows.

</details>

**4. Why must the app's database role not own the tables or have `BYPASSRLS`?**

<details><summary>Answer</summary>

Those roles can skip the policies, so RLS would silently do nothing. `FORCE ROW LEVEL SECURITY` covers owners, but `BYPASSRLS` and superusers still skip policies.

</details>

**5. Why set the tenant per transaction when using a connection pool?**

<details><summary>Answer</summary>

Connections are reused. A session-level value could stay on the connection and expose one tenant's context to the next request.

</details>
