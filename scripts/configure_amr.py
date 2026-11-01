"""Tell Keycloak to report how each user signed in, in the token's amr claim.

Keycloak leaves amr empty until each login step has a reference label. This runs inside the
container and uses the container's own environment, so no password passes through here.

Run:  uv run python scripts/configure_amr.py
"""

import json
import subprocess
import sys

sys.path.insert(0, ".")
from scripts.livecheck import ROOT  # noqa: E402

KCADM = "/opt/keycloak/bin/kcadm.sh"
SIGN_IN = (
    f"{KCADM} config credentials --server http://localhost:8080 --realm master "
    '--user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" '
    "--config /tmp/kcadm.config >/dev/null 2>&1"
)
REFERENCES = {"auth-username-password-form": "pwd", "auth-otp-form": "otp"}
# The mapper only reports a login step while it is younger than this.
MAX_AGE_SECONDS = 36000


def in_container(command: str) -> str:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "keycloak", "sh", "-c", f"{SIGN_IN} && {command}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def main() -> None:
    executions = json.loads(
        in_container(
            f"{KCADM} get authentication/flows/browser/executions -r course "
            "--config /tmp/kcadm.config"
        )
    )
    for execution in executions:
        reference = REFERENCES.get(execution.get("providerId"))
        if reference is None:
            continue
        settings = (
            f"-s 'config.\"default.reference.value\"={reference}' "
            f"-s 'config.\"default.reference.maxAge\"={MAX_AGE_SECONDS}' "
            "--config /tmp/kcadm.config"
        )
        config_id = execution.get("authenticationConfig")
        if config_id:
            in_container(f"{KCADM} update authentication/config/{config_id} -r course {settings}")
        else:
            in_container(
                f"{KCADM} create authentication/executions/{execution['id']}/config -r course "
                f"-s alias=reference-{reference} {settings}"
            )
        print(f"Labelled {execution['providerId']} as {reference}")


if __name__ == "__main__":
    main()
