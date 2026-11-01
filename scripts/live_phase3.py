"""Live check for App 2 against the real local Keycloak.

Run:  uv run python scripts/live_phase3.py
"""

import asyncio
import sys
import threading

import httpx

sys.path.insert(0, ".")
from apps.app2_oidc import device_cli, worker  # noqa: E402
from apps.app2_oidc.oidc import OidcProvider  # noqa: E402
from apps.app2_oidc.settings import settings  # noqa: E402
from scripts.keycloak_browser import accept_consent, browser, sign_in  # noqa: E402
from scripts.livecheck import Report, servers  # noqa: E402


def device_flow(report: Report) -> None:
    async def run() -> dict:
        metadata = await OidcProvider(settings.issuer).metadata()
        async with httpx.AsyncClient(timeout=15) as http:
            device = await device_cli.start(http, metadata)

            def approve() -> None:
                with browser() as person:
                    page = person.get(device["verification_uri_complete"])
                    consent = sign_in(person, page, "asha")
                    accept_consent(person, consent)

            thread = threading.Thread(target=approve)
            thread.start()
            tokens = await asyncio.wait_for(device_cli.poll(http, metadata, device), 30)
            thread.join()
            return tokens

    report.check("Device flow gives a CLI a token", "access_token" in asyncio.run(run()))


def main() -> None:
    report = Report()
    with servers(
        ("apps.app2_oidc.manual_flow:app", 8002),
        ("apps.app2_oidc.library_flow:app", 8012),
        ("apps.app2_oidc.api:app", 8022),
    ):
        with browser() as person:
            login_page = person.get("http://localhost:8002/login")
            report.check("App redirects to Keycloak", "realms/course" in str(login_page.url))
            back = sign_in(person, login_page, "asha")
            report.check("Hand-written login returns to the app", "asha" in back.text)

            cookie_names = {
                cookie.name
                for cookie in person.cookies.jar
                if cookie.domain.startswith("localhost")
            }
            profile = person.get("http://localhost:8002/profile")
            report.check("Profile shows the user", profile.json()["name"] == "asha")
            report.check("No token reaches the browser", "eyJ" not in profile.text + back.text)
            report.check("Session cookie is set", "app2_session" in cookie_names)

            person.post("http://localhost:8002/logout")
            after = person.get("http://localhost:8002/profile")
            report.check("Sign-out ends the app session", after.status_code == 401)
            relogin = person.get("http://localhost:8002/login")
            report.check(
                "Sign-out also ended Keycloak's session", 'name="username"' in relogin.text
            )

        with browser() as person:
            page = person.get("http://localhost:8012/login")
            back = sign_in(person, page, "asha")
            report.check("Authlib login works", back.json().get("name") == "asha")

        report.check("Worker reaches the API with no user", "subject" in asyncio.run(worker.main()))
        device_flow(report)

        report.check(
            "API rejects a request with no token",
            httpx.get("http://localhost:8022/api/whoami").status_code == 401,
        )
    report.finish()


if __name__ == "__main__":
    main()
