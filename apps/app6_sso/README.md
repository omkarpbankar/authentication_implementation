# App 6: SSO, SAML, and Provisioning

Two apps sharing one login. The lesson is [Phase 7](../../journey/phase-07-sso-saml.md).

| File | Port | Purpose |
|---|---|---|
| `oidc_app.py` | 8006 | An OIDC app with just-in-time provisioning, back-channel logout, and silent SSO |
| `scim.py` | 8006 | A SCIM 2.0 endpoint for company directories |
| `directory.py` | | The app's copy of its users |
| `saml_app/main.py` | 8007 | A SAML Service Provider, in a Linux container |

```powershell
uv run python scripts/reset_realm.py
docker compose --profile saml up -d --build saml-app
uv run uvicorn apps.app6_sso.oidc_app:app --port 8006
```

Open http://localhost:8006/login, sign in as `asha`, then open http://localhost:8007/saml/login and notice there is no second password.

| Check | Command |
|---|---|
| Unit tests | `uv run pytest tests/app6_sso -v` |
| SAML attack lab | `docker compose --profile saml run --rm --no-deps saml-app pytest tests/app6_saml -v` |
| Live flow | `uv run python scripts/live_phase7.py` |

## Lessons from running this for real

- **Repeated attributes:** Keycloak's role mapper repeats the attribute name by default, and `python3-saml` rejects that in strict mode. Fix it on the IdP by using a single attribute, not by weakening the check.
- **Rebuilt realm:** A rebuilt realm gets new signing keys, so the SAML app must restart to fetch the new certificate. `reset_realm.py` does this.
- **Container reachability:** Keycloak reaches your PC through `host.docker.internal` for back-channel logout.

## Connecting Entra ID and Okta

These need your own accounts.

**Entra ID as a SAML IdP:**
1. Open **Enterprise applications**, and create your own non-gallery application.
2. Choose **Single sign-on**, then **SAML**.
3. Set the Identifier to `http://localhost:8007/saml/metadata`, and the Reply URL to `http://localhost:8007/saml/acs`.
4. Download the Base64 certificate, and pass it to `build_settings`, with Entra's entity ID.

**Entra ID behind Keycloak (brokering):** In Keycloak, add an OpenID Connect identity provider that points at your Entra tenant. Your apps do not change, which is the benefit of brokering.

**Licensing:** Check Microsoft's current feature comparison first. Reports conflict on custom SAML apps on the free tier, and provisioning may need a paid license.
