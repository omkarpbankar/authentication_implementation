# Phase 9: Permissions and RBAC

**Goal:** Control what each signed-in person can do.
**You will build:** Permissions for App 7.

## The big idea

Think of job titles at a hospital. Instead of listing every door each person may open, the hospital says "nurses can do these things", then gives a person the nurse role. That is **Role-Based Access Control**.

The chain is: **user → role → permissions**. Your code checks permissions, such as `document:delete`, rather than role names, so changing a role never requires a code change.

## Learn in this order

1. **401 vs 403.** Revisit these from Phase 1.
2. **RBAC.** Users, roles, and permissions.
3. **BOLA/IDOR.** Holding a permission is not enough. The user must also have rights to that specific record.
4. **Ownership.** Authors can edit their own documents.
5. **ABAC.** Decisions based on attributes, such as clearance level.
6. **ReBAC.** Decisions based on relationships, as in Google Docs sharing.
7. **Escalation.** An admin must not be able to give themselves more power.
8. **Permission changes.** How quickly a removal takes effect while tokens are still alive.

## What you will build

Build `require_permission()`, map each provider's roles to one shared `Principal`, add ownership and ABAC rules, block privilege escalation, and generate a test for every role on every route.

## Run it

The permissions are in App 7, and `migrations/versions/0003_rbac.py` holds the role table.

```powershell
uv run pytest tests/app7_platform/test_permissions.py -v
```

That test runs every role against every route, checking both allowed and denied outcomes. `casbin_comparison.py` shows the same rules in a policy engine, and a test confirms that both reach the same decisions.

## Small test

Pass mark: 4 of 5.

**1. Why check permissions rather than role names in code?**

<details><summary>Answer</summary>

You can change what a role includes by editing data, without touching code.

</details>

**2. A user with `document:read` changes `/documents/5` to `/documents/6` and sees a stranger's file. What is this bug?**

<details><summary>Answer</summary>

BOLA, also called IDOR. The app checked the permission, but not access to that specific document.

</details>

**3. When is ReBAC a better fit than RBAC?**

<details><summary>Answer</summary>

When access depends on relationships, such as sharing individual documents with particular people or teams.

</details>

**4. An Admin tries to promote themselves to Owner. What should happen, and where is this enforced?**

<details><summary>Answer</summary>

It should be refused, and enforced on the server. Hiding a button is not security.

</details>

**5. Why test denied cases as well as allowed cases?**

<details><summary>Answer</summary>

A missing check does not break normal use. Only a denied-case test reveals that someone has access they should not.

</details>
