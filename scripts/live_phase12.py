"""Live check for Phase 12: rate limits, a leaked-key drill, outages, TLS, backup, and load.

Run:  uv run python scripts/live_phase12.py
"""

import asyncio
import secrets
import statistics
import subprocess
import sys
import time

import httpx

sys.path.insert(0, ".")
from apps.app8_access.catalog import NOTES_ID  # noqa: E402
from scripts.keycloak_browser import browser, sign_in  # noqa: E402
from scripts.livecheck import ROOT, Report, servers  # noqa: E402

API = "http://localhost:8001"
ACCESS = "http://localhost:8010"
NOTES = "http://localhost:8012"
TOKEN_URL = "http://localhost:8080/realms/course/protocol/openid-connect/token"
PASSWORD = "correct-horse-battery"
LOAD_REQUESTS = 400
# One instance handles about 110 decisions a second. This is normal load for one instance.
LOAD_CONCURRENCY = 5
TARGET_P95_MS = 250


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args], cwd=ROOT, check=check, capture_output=True, text=True
    )


def sign_up(email: str) -> dict:
    httpx.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD})
    return httpx.post(f"{API}/auth/login", data={"username": email, "password": PASSWORD}).json()


def leaked_key_drill(report: Report) -> None:
    """Follows docs/runbooks/leaked-signing-key.md."""
    email = f"drill-{secrets.token_hex(4)}@example.com"
    pair = sign_up(email)
    headers = {"Authorization": f"Bearer {pair['access_token']}"}
    report.check(
        "Drill: token works before the leak",
        httpx.get(f"{API}/users/me", headers=headers).status_code == 200,
    )

    started = time.time()
    subprocess.run(
        [sys.executable, "-m", "apps.app1_jwt.rotate_keys", "--emergency"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    blocked = httpx.get(f"{API}/users/me", headers=headers).status_code == 401
    report.check(f"Drill: old tokens stop in {time.time() - started:.1f} seconds", blocked)

    fresh = httpx.post(f"{API}/auth/login", data={"username": email, "password": PASSWORD}).json()
    new_headers = {"Authorization": f"Bearer {fresh['access_token']}"}
    report.check(
        "Drill: users can sign in again at once",
        httpx.get(f"{API}/users/me", headers=new_headers).status_code == 200,
    )
    keys = httpx.get(f"{API}/.well-known/jwks.json").json()["keys"]
    report.check("Drill: only the new key is published", len(keys) == 1)


def rate_limit_check(report: Report) -> None:
    email = f"limit-{secrets.token_hex(4)}@example.com"
    sign_up(email)
    codes = [
        httpx.post(f"{API}/auth/login", data={"username": email, "password": "wrong"}).status_code
        # More than twice the limit, because the count resets on each new minute.
        for _ in range(22)
    ]
    report.check("Guessing is slowed down with a 429", 429 in codes)
    report.check(
        "Security headers are present", "x-frame-options" in httpx.get(f"{API}/docs").headers
    )


async def load_test(report: Report) -> None:
    token = httpx.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": "notes-app",
            "client_secret": "notes-app-dev-secret",
        },
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    semaphore = asyncio.Semaphore(LOAD_CONCURRENCY)
    timings: list[float] = []
    failures = 0

    async def one(http: httpx.AsyncClient, number: int) -> None:
        nonlocal failures
        body = {
            "subject": {"type": "user", "id": f"load-{number % 50}", "properties": {}},
            "resource": {"type": "application", "id": str(NOTES_ID)},
            "context": {"tenant": "acme", "feature": "notes.read"},
        }
        async with semaphore:
            started = time.perf_counter()
            response = await http.post(f"{ACCESS}/access/v1/evaluation", json=body, headers=headers)
            timings.append((time.perf_counter() - started) * 1000)
            failures += response.status_code != 200

    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=30) as http:
        await asyncio.gather(*(one(http, number) for number in range(LOAD_REQUESTS)))
    duration = time.perf_counter() - started

    timings.sort()
    p50 = statistics.median(timings)
    p95 = timings[int(len(timings) * 0.95)]
    print(
        f"  {LOAD_REQUESTS / duration:.0f} decisions per second, p50 {p50:.0f} ms, p95 {p95:.0f} ms"
    )
    report.check("Load test: no failed requests", failures == 0)
    report.check(f"Load test: p95 is under {TARGET_P95_MS} ms", p95 < TARGET_P95_MS)


def backup_check(report: Report) -> None:
    script = """
    set -e
    export PGUSER="$POSTGRES_USER"
    dropdb --if-exists access_restore_check
    createdb access_restore_check
    pg_dump -d access --no-owner --no-privileges | psql -q -d access_restore_check >/dev/null
    psql -tA -d access -c "SELECT count(*) FROM tiers"
    psql -tA -d access_restore_check -c "SELECT count(*) FROM tiers"
    dropdb access_restore_check
    """
    result = compose("exec", "-T", "postgres", "sh", "-c", script, check=False)
    lines = result.stdout.split()
    report.check(
        f"Backup restores into a clean database ({lines[-1] if lines else '?'} tiers)",
        result.returncode == 0 and len(lines) >= 2 and lines[-1] == lines[-2],
    )


def outage_check(report: Report) -> None:
    """With the Access Service stopped, a signed-in user must get an honest outage message."""
    with servers(("apps.app8_access.notes_app.main:app", 8012)):
        with browser() as person:
            page = sign_in(person, person.get(f"{NOTES}/"), "vik")
            report.check(
                "Outage: apps fail closed with a 503",
                page.status_code == 503 and "temporarily unavailable" in page.text,
            )
            report.check(
                "Outage: the user is not told they are unauthorized",
                "not authorized" not in page.text,
            )


def main() -> None:
    report = Report()
    with servers(("apps.app1_jwt.main:app", 8001)):
        rate_limit_check(report)
        leaked_key_drill(report)

    with servers(("apps.app8_access.access_service.main:app", 8010)):
        ready = httpx.get(f"{ACCESS}/health/ready").json()
        report.check("Readiness reports healthy", ready == {"status": "ok", "cache": "ok"})
        asyncio.run(load_test(report))

    outage_check(report)
    backup_check(report)
    report.finish()


if __name__ == "__main__":
    main()
