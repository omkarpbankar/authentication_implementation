"""Rebuild the course realm in Keycloak from scripts/build_realm.py.

This replaces anything you changed by hand in the course realm.
Run:  uv run python scripts/reset_realm.py
"""

import subprocess
import sys

sys.path.insert(0, ".")
from scripts.livecheck import ROOT  # noqa: E402


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", *args], cwd=ROOT, check=True)


if __name__ == "__main__":
    subprocess.run([sys.executable, "scripts/build_realm.py"], cwd=ROOT, check=True)
    compose("stop", "keycloak")
    compose(
        "run",
        "--rm",
        "keycloak",
        "import",
        "--dir",
        "/opt/keycloak/data/import",
        "--override",
        "true",
    )
    compose("up", "-d", "--wait", "keycloak")
    subprocess.run([sys.executable, "scripts/configure_amr.py"], cwd=ROOT, check=True)
    # A rebuilt realm gets new signing keys, so the SAML app must fetch the new certificate.
    subprocess.run(
        ["docker", "compose", "--profile", "saml", "restart", "saml-app"], cwd=ROOT, check=False
    )
    print("Course realm is ready at http://localhost:8080/realms/course")
