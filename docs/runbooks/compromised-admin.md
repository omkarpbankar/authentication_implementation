# Runbook: Compromised Admin Account

Written for: the on-call engineer and security contact. Use this if an admin account may be under someone else's control.

**Signs:** Sign-ins from unusual places, access changes nobody requested, new admins, or an alert from `deploy/alerts.yml`.

## 1. Stop the damage

Have a different Super Admin do this.

1. Remove the admin role in the panel under **Admins**. The next admin action is denied at once.
2. In Keycloak, disable the user and end their sessions.
3. If a Super Admin is compromised and no other is available, use break-glass: run `apps.app8_access.access_service.bootstrap_admin` from a trusted machine to promote a known person.

Keep at least one Super Admin at all times. The panel blocks removing the last one.

## 2. Find what changed

In the panel, open **Audit log**, or query the data directly:

```sql
SELECT at, action, target, reason, before, after
FROM access_audit_log
WHERE actor_id = '<admin user id>'
ORDER BY at;
```

The audit log is append-only for the app, so it can be trusted even if the admin account was misused.

## 3. Undo the changes

Reverse each unauthorized grant, role change, and tier change. Each one needs a reason that refers to this incident.

Check for lasting access that an attacker may have left behind: new admins, group changes, and long-lived grants.

## 4. Recover the account

1. Confirm the person's identity outside the compromised channel, such as by phone.
2. Reset their password and MFA, and move them to a passkey if you can.
3. Restore the admin role only once the investigation is finished.

## 5. Follow up

Notify affected tenants if their data or access was touched, and write a blameless review.
