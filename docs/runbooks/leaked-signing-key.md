# Runbook: Leaked Signing Key

Written for: the on-call engineer. Use this if a private signing key may have been exposed.

**Why this is urgent:** Anyone with the key can create a token for any user. Treat every token signed by it as forged.

Practiced by `scripts/live_phase12.py`, where old tokens stopped working in about 3 seconds.

## 1. Stop the damage

Do this first, even before you are certain. A false alarm only signs people out.

```powershell
uv run python -m apps.app1_jwt.rotate_keys --emergency
```

This creates a new key and removes all older ones. Running servers notice the change on the next request.

Confirm that old tokens fail, and that only one key is published:

```powershell
curl.exe http://localhost:8001/.well-known/jwks.json
```

Other services cache public keys, so restart any that verify these tokens if they keep accepting old ones.

## 2. Check that users can return

Sign in with a test account, and confirm that a new token works. All existing access tokens stop working. Refresh tokens are not signed by this key, so clients holding one can get a new access token without another sign-in.

If you suspect sessions were also stolen, end those too, using `revoke_everything` for affected users.

## 3. Investigate

- How did the key leak? Check repository history, CI logs, backups, and who had access.
- Search the audit log for unusual activity from the time of the suspected leak.
- Look for grants, role changes, or new admins that nobody recognizes.

## 4. Fix the cause

- Remove the leaked key from wherever it was exposed. If it reached Git, treat history as public.
- Reverse any unauthorized changes.
- Move signing keys into a key management service, so they never exist as files.

## 5. Follow up

- Tell affected customers, following your legal and contractual duties.
- Write a blameless review, including what would have caught this sooner.
- Rehearse this runbook again.
