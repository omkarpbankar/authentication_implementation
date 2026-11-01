# Phase 1: Fundamentals

Three small exercises. The full walkthrough is in [the Phase 1 lesson](../../journey/phase-01-fundamentals.md).

| Exercise | File | Port | Demonstrates |
|---|---|---|---|
| HTTP Basic | `exercise1_basic_auth.py` | 8101 | Password hashing, identical login errors, Base64 is not encryption |
| Sessions | `exercise2_sessions.py` | 8102 | Server-side sessions in Redis, cookie flags, instant revocation |
| CSRF lab | `csrf_lab/bank.py` | 8103 | When `SameSite=Lax` helps, when it does not, and CSRF tokens |

The practice attacker page runs from `csrf_lab/evil_site/` on port 8104.

Practice accounts: username `asha`, password `correct-horse-battery`. These are public demo values.

Run the tests with `uv run pytest tests/phase1 -v`.
