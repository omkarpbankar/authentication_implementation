"""Live check for App 1, using a real server, real Redis, and a separate verifier service.

Run:  uv run python scripts/live_phase2.py
"""

import secrets
import subprocess
import sys

import httpx

sys.path.insert(0, ".")
from scripts.livecheck import ROOT, Report, servers  # noqa: E402

API = "http://localhost:8001"
VERIFIER = "http://localhost:8011"


def main() -> None:
    report = Report()
    email = f"live-{secrets.token_hex(4)}@example.com"
    password = "correct-horse-battery"

    with servers(
        ("apps.app1_jwt.main:app", 8001),
        ("apps.app1_jwt.verifier_service:app", 8011),
    ):
        httpx.post(f"{API}/auth/register", json={"email": email, "password": password})
        pair = httpx.post(
            f"{API}/auth/login", data={"username": email, "password": password}
        ).json()
        headers = {"Authorization": f"Bearer {pair['access_token']}"}

        report.check(
            "Sign-in returns a working token",
            httpx.get(f"{API}/users/me", headers=headers).status_code == 200,
        )
        report.check(
            "Verifier accepts it using only the public JWKS",
            httpx.get(f"{VERIFIER}/whoami", headers=headers).status_code == 200,
        )
        report.check(
            "Verifier rejects a forged token",
            httpx.get(
                f"{VERIFIER}/whoami", headers={"Authorization": "Bearer abc.def.ghi"}
            ).status_code
            == 401,
        )

        subprocess.run([sys.executable, "-m", "apps.app1_jwt.rotate_keys"], cwd=ROOT, check=True)
        report.check(
            "Old token still works after key rotation",
            httpx.get(f"{API}/users/me", headers=headers).status_code == 200,
        )

        newer = httpx.post(
            f"{API}/auth/refresh", json={"refresh_token": pair["refresh_token"]}
        ).json()
        new_headers = {"Authorization": f"Bearer {newer['access_token']}"}
        report.check(
            "Refreshed token signed by the new key works",
            httpx.get(f"{API}/users/me", headers=new_headers).status_code == 200,
        )

        replay = httpx.post(f"{API}/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        report.check("Replayed refresh token is rejected", replay.status_code == 401)
        family = httpx.post(f"{API}/auth/refresh", json={"refresh_token": newer["refresh_token"]})
        report.check("Replay also cancelled the newer refresh token", family.status_code == 401)

        httpx.post(f"{API}/auth/logout", headers=new_headers)
        report.check(
            "Access token stops working after logout",
            httpx.get(f"{API}/users/me", headers=new_headers).status_code == 401,
        )

    report.finish()


if __name__ == "__main__":
    main()
