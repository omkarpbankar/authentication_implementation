# App 5 Setup: Connect Real Providers

App 5 already runs with the local Keycloak, which needs no setup. Each provider below is free, and appears on the sign-in page once its client ID is set.

Create `apps/app5_social/.env`, which Git ignores, and add the values as you go.

## Google

1. In the [Google Cloud Console](https://console.cloud.google.com), create a project.
2. Configure the OAuth consent screen, and add yourself as a test user.
3. Create an **OAuth client ID** of type **Web application**.
4. Add the redirect URI `http://localhost:8005/callback/google`.
5. To try the calendar step, enable the Google Calendar API, and add the `calendar.readonly` scope.

```
APP5_GOOGLE_CLIENT_ID=...
APP5_GOOGLE_CLIENT_SECRET=...
```

In Testing mode, only listed test users can sign in, and refresh tokens expire after 7 days.

## Microsoft personal accounts

1. In the [Entra admin center](https://entra.microsoft.com), create a new app registration.
2. Choose **Personal Microsoft accounts only**.
3. Add a **Web** redirect URI: `http://localhost:8005/callback/microsoft`.
4. Create a client secret.

```
APP5_MICROSOFT_CLIENT_ID=...
APP5_MICROSOFT_CLIENT_SECRET=...
```

## GitHub

1. Open **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Set the callback URL to `http://localhost:8005/callback/github`.
3. Generate a client secret.

```
APP5_GITHUB_CLIENT_ID=...
APP5_GITHUB_CLIENT_SECRET=...
```

## Adding another OIDC provider

Add one line to `oidc_providers` in `providers.py`, plus its settings. Nothing else changes.
