# Token and Session Lifetimes

Written for: engineers operating these apps.

| Item | Lifetime | Why | Set in |
|---|---|---|---|
| App 1 access token | 10 minutes | Limits damage if stolen | `apps/app1_jwt/settings.py` |
| App 1 refresh token | 14 days, rotates on each use | Keeps users signed in, and reveals theft | `apps/app1_jwt/settings.py` |
| App 7 tenant token | 5 minutes | Membership is rechecked each request anyway | `apps/app7_platform/settings.py` |
| Keycloak access token | 5 minutes | Short, because it cannot be revoked | `scripts/build_realm.py` |
| App session | 1 hour | Normal working session | Each app |
| Admin session, idle | 15 minutes | Admins hold more power | `apps/app8_access/admin_panel/main.py` |
| Admin session, total | 8 hours | One working day | `apps/app8_access/admin_panel/main.py` |
| Sensitive admin action | Sign-in within 15 minutes | Proves the admin is still present | `apps/app8_access/access_service/settings.py` |
| Step-up MFA | 5 minutes | One sensitive task at a time | `apps/app1_jwt/store.py` |
| Login attempt | 5 minutes | State and nonce are short-lived | `apps/app2_oidc/sessions.py` |
| Magic link, password reset | 15 minutes, single use | Email is a weak channel | `apps/app1_jwt/links.py` |
| API key | Up to 365 days, 90 by default | Forces rotation | `apps/app1_jwt/api_keys.py` |
| Access decision cache | 30 seconds, cleared by a version change | Limits the Access Service's load | `apps/app8_access/access_service/settings.py` |
| Clock allowance | 30 seconds | Servers never agree on the time exactly | `apps/app2_oidc/oidc.py` |

**Changing a value:** Shorter is safer but means more sign-ins and more load. Change one at a time, and watch sign-in failures afterward.

**Audit log retention:** Keep at least one year, or longer if your contracts or regulations require it. The app role cannot delete rows, so retention is a job for a separate privileged process.
