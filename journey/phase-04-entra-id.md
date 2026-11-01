# Phase 4: Microsoft Entra ID (Azure AD)

**Goal:** Use the login system most large companies run on.
**You will build:** App 3, enterprise sign-in and a protected API.

## The big idea

Azure Active Directory is now called **Microsoft Entra ID**. Picture a company's staff directory and security desk, run by Microsoft. Each company gets its own private directory, called a **tenant**.

To use it, your app must be registered, which is like getting a visitor badge for your app. Registration gives your app its **client ID**.

## Learn in this order

1. **Key IDs.** Tenant ID (`tid`) is the directory, client ID is your app, and object ID (`oid`) is the user.
2. **App registration vs enterprise application.** The first is your app's global definition. The second is its presence in one tenant.
3. **Delegated vs application permissions.** Delegated means acting for a signed-in user (`scp`). Application means acting as itself, with no user (`roles`).
4. **App roles.** Roles such as Reader and Writer that you define, and assign to people.
5. **Your own API scope.** Your API needs its own scope, such as `api://<client-id>/access_as_user`.
6. **On-Behalf-Of.** Your API calls another API as the signed-in user.
7. **Which product?** Entra ID is for staff, and Entra External ID is for customers. Azure AD B2C closed to new customers in May 2025.

## What you will build

Register an app, sign users in with MSAL, protect your own API, enforce Reader and Writer roles, run a background job with no user, and call Microsoft Graph on behalf of a user.

## Before you start

You need an Azure account with an Entra tenant. Create only test users, and check Microsoft's current docs, since the portal changes often.

## Run it

The code is in [apps/app3_entra/](../apps/app3_entra/). It was tested against a simulated provider that issues real signed tokens in Entra's format.

```powershell
uv run pytest tests/app3_entra -v
```

**Your step:** Follow [the setup guide](../apps/app3_entra/SETUP.md) to connect your own tenant. This has not run against real Microsoft Entra ID yet.

## Small test

Pass mark: 4 of 5.

**1. What is a tenant in Entra ID?**

<details><summary>Answer</summary>

A private directory for one organization, holding its users, groups, and apps. It is identified by a tenant ID.

</details>

**2. What is the difference between delegated and application permissions?**

<details><summary>Answer</summary>

Delegated permissions act for a signed-in user and are limited by that user. Application permissions let an app act as itself with no user.

</details>

**3. Why shouldn't your API validate a token issued for Microsoft Graph?**

<details><summary>Answer</summary>

That token was issued for Graph, so its audience is Graph. Your API should only accept tokens issued for your API's own scope.

</details>

**4. In a multi-tenant app, why check `tid` yourself?**

<details><summary>Answer</summary>

Any Microsoft organization could get a valid token. You must confirm that the user's tenant is one you allow.

</details>

**5. A company wants customers, not staff, to sign up to its app. Which Microsoft product fits?**

<details><summary>Answer</summary>

Microsoft Entra External ID. Azure AD B2C is closed to new customers, and Entra ID is meant for workforce identity.

</details>
