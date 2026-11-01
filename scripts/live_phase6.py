"""Live check for App 5, using the real local Keycloak as the third-party provider.

Run:  uv run python scripts/live_phase6.py
"""

import subprocess
import sys

sys.path.insert(0, ".")
from scripts.keycloak_browser import browser, sign_in  # noqa: E402
from scripts.livecheck import ROOT, Report, servers  # noqa: E402

APP = "http://localhost:8005"


def main() -> None:
    report = Report()
    # A rebuilt realm gives users new IDs, and old accounts would rightly refuse to merge.
    subprocess.run(
        ["docker", "compose", "exec", "-T", "redis", "redis-cli", "-n", "5", "flushdb"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    with servers(("apps.app5_social.main:app", 8005)):
        with browser() as person:
            report.check("Sign-in page lists Keycloak", "Keycloak" in person.get(APP).text)
            back = sign_in(person, person.get(f"{APP}/login/keycloak"), "asha")
            account = back.json()
            report.check("Sign-in creates an account", account["logins"] == ["keycloak"])
            report.check("Verified email is recorded", account["email"] == "asha@acme.example")

            removed = person.post(
                f"{APP}/unlink/keycloak", data={"csrf_token": account["csrf_token"]}
            )
            report.check("The only login method cannot be removed", removed.status_code == 409)
            forged = person.post(f"{APP}/unlink/keycloak", data={"csrf_token": "wrong"})
            report.check("Missing CSRF token is rejected", forged.status_code == 403)

            person.post(f"{APP}/logout")
            report.check("Sign-out works", person.get(f"{APP}/account").status_code == 401)

        with browser() as person:
            back = sign_in(person, person.get(f"{APP}/login/keycloak"), "neha")
            report.check("Unverified email is not stored", back.json()["email"] == "")
    report.finish()


if __name__ == "__main__":
    main()
