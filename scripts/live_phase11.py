"""Live check for App 8: all services running, with real Keycloak, Postgres, Redis, and MFA.

Run:  uv run python scripts/reset_realm.py
      uv run python scripts/setup_access_db.py
      uv run python scripts/live_phase11.py
"""

import asyncio
import base64
import re
import subprocess
import sys
import time
from urllib.parse import urljoin

import httpx
import pyotp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, ".")
from apps.app8_access.access_service.bootstrap_admin import promote  # noqa: E402
from apps.app8_access.catalog import NOTES_ID  # noqa: E402
from scripts.build_realm import ADMIN_TOTP_SECRET  # noqa: E402
from scripts.keycloak_browser import browser, form_action, sign_in  # noqa: E402
from scripts.livecheck import ROOT, Report, servers  # noqa: E402

ACCESS = "http://localhost:8010"
PANEL = "http://localhost:8011"
NOTES = "http://localhost:8012"
REPORTS = "http://localhost:8013"
FILES = "http://localhost:8014"
NOT_AUTHORIZED = "You are not authorized to use this application. Please check with your admin."

totp = pyotp.TOTP(base64.b32encode(ADMIN_TOTP_SECRET.encode()).decode())


def sign_in_with_otp(person: httpx.Client, page: httpx.Response) -> httpx.Response:
    after_password = sign_in(person, page, "meera")
    if 'name="otp"' not in after_password.text:
        return after_password
    action = urljoin(str(after_password.url), form_action(after_password.text))
    # A code can only be used once, so the next sign-in waits for a fresh one.
    return person.post(action, data={"otp": totp.now()})


def wait_for_new_code() -> None:
    current = totp.now()
    while totp.now() == current:
        time.sleep(0.5)


def csrf(page: httpx.Response) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def clear_earlier_runs() -> None:
    """Grants and requests from a previous run would change what this one sees."""
    url = "postgresql+asyncpg://access_owner:access-owner-dev-password@127.0.0.1:5433/access"

    async def go() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as db:
            tenants = (await db.execute(text("SELECT id FROM tenants"))).scalars().all()
        for tenant_id in tenants:
            async with engine.begin() as db:
                await db.execute(
                    text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_id)}
                )
                for table in ("access_requests", "user_app_access", "admin_roles", "tenant_users"):
                    await db.execute(text(f"DELETE FROM {table}"))
        # A rebuilt realm gives people new IDs, so old records would be duplicates.
        async with engine.begin() as db:
            await db.execute(text("DELETE FROM users"))
        await engine.dispose()

    asyncio.run(go())
    subprocess.run(
        ["docker", "compose", "exec", "-T", "redis", "redis-cli", "-n", "8", "flushdb"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def main() -> None:
    report = Report()
    clear_earlier_runs()
    with servers(
        ("apps.app8_access.access_service.main:app", 8010),
        ("apps.app8_access.admin_panel.main:app", 8011),
        ("apps.app8_access.notes_app.main:app", 8012),
        ("apps.app8_access.reports_app.main:app", 8013),
        ("apps.app8_access.files_app.main:app", 8014),
    ):
        vik = browser()
        page = sign_in(vik, vik.get(f"{NOTES}/"), "vik")
        report.check(
            "Signed-in user with no grant sees the exact message",
            page.status_code == 403 and NOT_AUTHORIZED in page.text.replace("&#x27;", "'"),
        )
        for name, url in (("Reports", REPORTS), ("Files", FILES)):
            other = vik.get(f"{url}/")
            report.check(
                f"{name} shows the same message through SSO, with no second password",
                other.status_code == 403 and NOT_AUTHORIZED in other.text,
            )

        reference = re.search(r"Reference: (\w+)", page.text).group(1)
        request = vik.post(f"{NOTES}/request-access", data={"note": "I joined the team"})
        report.check("User can request access", request.status_code == 202)

        meera = browser()
        first = sign_in_with_otp(meera, meera.get(f"{NOTES}/"))
        report.check("A real TOTP code passes Keycloak", first.status_code == 403)
        print(" ", asyncio.run(promote("meera@acme.example", "acme")))

        wait_for_new_code()
        meera = browser()
        dashboard = sign_in_with_otp(meera, meera.get(f"{PANEL}/"))
        report.check(
            "Super Admin signs in to the panel with MFA",
            dashboard.status_code == 200 and "pending requests" in dashboard.text,
        )

        neel = browser()
        refused = sign_in(neel, neel.get(f"{PANEL}/login"), "neel")
        report.check(
            "Password alone cannot enter the panel",
            refused.status_code == 403 and "Multi-factor" in refused.text,
        )

        found = meera.get(f"{PANEL}/audit", params={"reference": reference})
        report.check(
            "A reference ID finds the denial in the audit log", "access.denied" in found.text
        )

        queue = meera.get(f"{PANEL}/requests")
        request_id = re.search(r"/requests/([0-9a-f-]{36})/approve", queue.text).group(1)
        report.check("The request appears in the queue", "I joined the team" in queue.text)
        token = csrf(queue)
        meera.post(
            f"{PANEL}/requests/{request_id}/approve",
            data={"csrf_token": token, "tier": "basic", "reason": "Approved for the team"},
        )

        opened = vik.get(f"{NOTES}/")
        report.check(
            "After approval the user gets in at Basic",
            opened.status_code == 200 and "Basic" in opened.text,
        )
        low = vik.get(f"{NOTES}/notes/export", headers={"Accept": "text/html"})
        report.check(
            "Basic cannot use a Premium feature",
            low.status_code == 403 and "not included in your Basic plan" in low.text,
        )

        users = meera.get(f"{PANEL}/users", params={"q": "vik"})
        user_id = re.search(r"/users/([0-9a-f-]{36})", users.text).group(1)
        detail = meera.get(f"{PANEL}/users/{user_id}")
        key = re.search(r'name="idempotency_key" value="([^"]+)"', detail.text).group(1)
        changed = meera.post(
            f"{PANEL}/users/{user_id}/grant",
            data={
                "csrf_token": token,
                "application_id": str(NOTES_ID),
                "tier": "premium",
                "reason": "Promoted",
                "idempotency_key": key,
            },
        )
        report.check("Admin changes the tier", changed.status_code == 200)

        upgraded = vik.get(f"{NOTES}/notes/export")
        report.check("Upgrade works with no new sign-in", upgraded.status_code == 200)

        revoked_at = time.time()
        meera.post(
            f"{PANEL}/users/{user_id}/grant-action",
            data={
                "csrf_token": token,
                "application_id": str(NOTES_ID),
                "action": "revoke",
                "reason": "No longer needed",
            },
        )
        locked_out = vik.get(f"{NOTES}/")
        elapsed = time.time() - revoked_at
        report.check(
            f"Revocation reaches a signed-in user in {elapsed:.2f} seconds",
            locked_out.status_code == 403 and elapsed < 30,
        )

        forged = meera.post(
            f"{PANEL}/users/{user_id}/disable",
            data={"csrf_token": "wrong", "reason": "forged request"},
        )
        report.check("The panel rejects a forged form", forged.status_code == 403)

        direct = httpx.get(f"{ACCESS}/admin/v1/users")
        report.check("The admin API refuses anonymous calls", direct.status_code == 401)
        report.check(
            "The audit log records the changes",
            "grant.revoked" in meera.get(f"{PANEL}/audit").text,
        )
    report.finish()


if __name__ == "__main__":
    main()
