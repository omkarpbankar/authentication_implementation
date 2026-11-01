# Runbook: Identity Provider Outage

Written for: the on-call engineer. Use this if Keycloak, Entra ID, or another IdP is unavailable.

## What users experience

| Who | Effect |
|---|---|
| Already signed in | Keep working until their session or token ends |
| Signing in | Cannot sign in |
| Apps calling the Access Service | Keep working until their service token expires, then fail closed |
| Admins | Cannot sign in, so grants cannot be changed |

## 1. Confirm the problem

```powershell
curl.exe -i http://localhost:8080/realms/course/.well-known/openid-configuration
docker compose ps keycloak
docker compose logs keycloak --tail 50
```

For a cloud IdP, check the provider's status page.

## 2. Tell people

Say what is affected, and that existing sessions keep working. Do not ask users to keep retrying.

## 3. Restore service

- **Self-hosted:** Restart Keycloak with `docker compose restart keycloak`, and check its database.
- **Cloud provider:** Wait for the provider, as you have no fix of your own.

Never disable token validation to get people back in. That removes all security at the moment attackers may be watching.

## 4. One customer's IdP is down

If only one company's IdP has failed, and that tenant enforces SSO, its users are locked out. Use break-glass for that tenant's admins only, and record the reason. Turn SSO enforcement back on as soon as their IdP returns.

## 5. If the Access Service is also down

Apps show "temporarily unavailable" and grant nothing, which is deliberate. Never configure apps to allow access when the service cannot answer.

## 6. Afterward

Check that sign-ins recovered, look for a backlog of failed logins, and write a blameless review.
