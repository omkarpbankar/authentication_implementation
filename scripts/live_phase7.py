"""Live check for App 6: real SSO across an OIDC app and a SAML app, using real Keycloak.

Run:  docker compose --profile saml up -d --build saml-app
      uv run python scripts/live_phase7.py
"""

import html
import re
import subprocess
import sys

import httpx

sys.path.insert(0, ".")
from apps.app6_sso.settings import settings  # noqa: E402
from scripts.keycloak_browser import browser, form_action, sign_in  # noqa: E402
from scripts.livecheck import ROOT, Report, servers, wait_for_port  # noqa: E402

OIDC = "http://localhost:8006"
SAML = "http://localhost:8007"
SCIM = {"Authorization": f"Bearer {settings.scim_token}"}


def post_saml_form(person: httpx.Client, page: httpx.Response) -> httpx.Response:
    """Browsers auto-submit this form. This does the same."""
    fields = dict(re.findall(r'name="(SAMLResponse|RelayState)"\s+value="([^"]*)"', page.text))
    data = {name: html.unescape(value) for name, value in fields.items()}
    return person.post(form_action(page.text), data=data)


def main() -> None:
    report = Report()
    # A rebuilt realm gives users new IDs, so earlier directory records no longer apply.
    subprocess.run(
        ["docker", "compose", "exec", "-T", "redis", "redis-cli", "-n", "6", "flushdb"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    wait_for_port(8007)
    with servers(("apps.app6_sso.oidc_app:app", 8006)):
        with browser() as person:
            back = sign_in(person, person.get(f"{OIDC}/login"), "asha")
            report.check("OIDC app signs in through Keycloak", back.json()["source"] == "jit")

            # The second app. Keycloak recognizes the session, so no login page appears.
            page = person.get(f"{SAML}/saml/login")
            report.check("SAML app needs no second sign-in", 'name="username"' not in page.text)
            profile = post_saml_form(person, page)
            user = profile.json()
            report.check("SAML assertion is accepted", profile.status_code == 200)
            report.check("Email arrives from the assertion", user["email"] == "asha@acme.example")
            report.check("Roles arrive from the assertion", "writer" in user["roles"])

            person.get(f"{SAML}/saml/logout")
            report.check(
                "SAML sign-out ends the SAML session",
                person.get(f"{SAML}/profile").status_code == 401,
            )
            report.check(
                "Back-channel logout also ended the OIDC session",
                person.get(f"{OIDC}/profile").status_code == 401,
            )

            relogin = person.get(f"{OIDC}/login")
            report.check("Keycloak's own session ended too", 'name="username"' in relogin.text)

        with browser() as person:
            sign_in(person, person.get(f"{OIDC}/login"), "ravi")
            found = httpx.get(
                f"{OIDC}/scim/v2/Users",
                params={"filter": 'userName eq "ravi@globex.example"'},
                headers=SCIM,
            ).json()
            user_id = found["Resources"][0]["id"]
            report.check("SCIM can see the provisioned user", found["totalResults"] == 1)

            patch = {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": False}],
            }
            httpx.patch(f"{OIDC}/scim/v2/Users/{user_id}", json=patch, headers=SCIM)
            report.check(
                "Deactivation ends the live session",
                person.get(f"{OIDC}/profile").status_code == 401,
            )

            blocked = person.get(f"{OIDC}/login")
            report.check(
                f"Deactivated user cannot sign back in (got {blocked.status_code})",
                blocked.status_code == 403,
            )

            restore = {**patch, "Operations": [{"op": "replace", "path": "active", "value": True}]}
            httpx.patch(f"{OIDC}/scim/v2/Users/{user_id}", json=restore, headers=SCIM)
    report.finish()


if __name__ == "__main__":
    main()
