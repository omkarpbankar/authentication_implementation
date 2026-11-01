# App 3 Setup: Connect Your Own Entra Tenant

This app has been tested against a simulated provider. These steps connect it to real Microsoft Entra ID. Portal wording changes often, so follow Microsoft's current screens if they differ.

Cost: a free Azure account with an Entra tenant is enough. Create test users, not real ones.

## 1. Register the API

1. In the [Entra admin center](https://entra.microsoft.com), go to **App registrations** and choose **New registration**.
2. Name it `app3-api`, choose single tenant, and register it.
3. Open **Expose an API**, and set the Application ID URI to `api://<client-id>`.
4. Add a scope called `access_as_user`.
5. Open **App roles**, and create `Reader` and `Writer`. Allow users and applications for both.
6. Open **Manifest**, and set `requestedAccessTokenVersion` (or `accessTokenAcceptedVersion`) to `2`.
7. Create a client secret under **Certificates & secrets** for the On-Behalf-Of step.

## 2. Register the web app

1. Create another registration named `app3-web`.
2. Add a **Web** redirect URI: `http://localhost:8003/callback`.
3. Create a client secret.
4. Under **API permissions**, add `access_as_user` from `app3-api`, as a delegated permission.
5. Add an application permission for the `Writer` role, and grant admin consent. This is for the daemon.

## 3. Assign roles

1. Create a test user.
2. Open **Enterprise applications**, then `app3-api`, then **Users and groups**.
3. Assign the test user the `Reader` role.

## 4. Configure the app

Create `apps/app3_entra/.env`, which Git ignores:

```
APP3_TENANT_ID=your-tenant-id
APP3_WEB_CLIENT_ID=your-web-client-id
APP3_WEB_CLIENT_SECRET=your-web-secret
APP3_API_CLIENT_ID=your-api-client-id
APP3_API_CLIENT_SECRET=your-api-secret
```

## 5. Run it

```powershell
uv run uvicorn apps.app3_entra.main:app --port 8003
uv run uvicorn apps.app3_entra.api:app --port 8013
```

Open http://localhost:8003 and sign in.

## 6. What to try

- Decode your access token at a JWT debugger you trust, and find `tid`, `oid`, `scp`, and `roles`.
- Call `POST /api/reports` as a `Reader`, and confirm a 403.
- Call `/api/graph-me` to see On-Behalf-Of.
- Run `uv run python -m apps.app3_entra.daemon`, and see that the token has no `scp`.
- In **Enterprise applications**, set **Assignment required** to Yes, and sign in as an unassigned user to see `AADSTS50105`.
