# Phase 12: Production Hardening

**Goal:** Take your apps from "works on my machine" to something you could defend in a design review.
**You will finish:** Apps 7 and 8.

## The big idea

Working code answers "does it do the right thing?". Production code must also answer "what happens when someone attacks it, something fails, or a key leaks?".

Think of a bank branch. The tellers are your features. The alarms, cameras, vault procedures, and fire drills are hardening. You hope never to need them, but you test them anyway.

## Learn in this order

1. **Abuse controls.** Rate limits and login throttling that do not let attackers lock out real users.
2. **Web protections.** CORS, CSRF, security headers, and safe redirects.
3. **Token lifecycle.** Documented lifetimes, session lists, and full revocation.
4. **Secrets.** Inject at runtime, and rotate regularly.
5. **Logging and audit.** Structured logs with no secrets, plus an append-only audit trail.
6. **Delivery.** Tests, scans, and a repeatable build in CI.
7. **Threat modeling.** Ask what could go wrong, using STRIDE.
8. **Standards.** Check your work against OWASP ASVS and the API Security Top 10.
9. **Incident runbooks.** Practice handling a leaked signing key.

## What you will build

Harden Apps 7 and 8, containerize them behind TLS, add CI, write a threat model, measure revocation speed under load, and run through a leaked-key drill.

## Run it

```powershell
uv run python scripts/live_phase12.py
```

This runs the leaked-key drill, rate limits, an Access Service outage, a backup and restore, and a load test.

To run two instances behind TLS, using `curl.exe -k` because the local certificate is private:

```powershell
docker compose -f docker-compose.yml -f deploy/docker-compose.prod.yml --profile prod up -d --build --wait access-1 access-2 proxy
curl.exe -k https://localhost:8443/health/ready
```

Read the results of this work in [docs/security/](../docs/security/) and [docs/runbooks/](../docs/runbooks/).

**Measured on this machine, with one instance:**

| Load | Median | 95th percentile |
|---|---|---|
| One request at a time | 15 ms | 16.5 ms |
| 5 at once | 38 ms | 50 ms |
| 20 at once, saturated | 244 ms | 760 ms |

One instance handles about 110 decisions a second, and the 30-second cache means most requests never reach it. The answer to more traffic is more instances.

**Learned while building:** The first version of this load test showed real waste, with about ten database round trips per decision. It now uses a single statement, and writes only when something has changed.

## Small test

Pass mark: 4 of 5.

**1. Why can strict account lockout be harmful?**

<details><summary>Answer</summary>

An attacker can lock real users out by deliberately failing logins. Gradual throttling and per-IP limits reduce this.

</details>

**2. Name three things that should never appear in logs.**

<details><summary>Answer</summary>

Any three of: passwords, tokens, session IDs, API keys, and other secrets.

</details>

**3. What is the first thing to do if your JWT signing key leaks?**

<details><summary>Answer</summary>

Treat all tokens signed with it as untrusted: remove the key from your JWKS, sign with a new key, and revoke sessions. Then investigate.

</details>

**4. Why must audit logs be append-only?**

<details><summary>Answer</summary>

So an attacker or insider cannot erase their tracks, and you can trust the record during an investigation.

</details>

**5. What is the purpose of a threat model?**

<details><summary>Answer</summary>

To think through what could go wrong, and how to reduce it, before an attacker finds out for you.

</details>
