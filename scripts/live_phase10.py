"""Live check for Phase 10: real emails to Mailpit, real TOTP codes, and a real mTLS handshake.

Run:  uv run python -m apps.mtls_lab.make_certs
      uv run python scripts/live_phase10.py
"""

import re
import secrets
import ssl
import subprocess
import sys
import time

import httpx
import pyotp

sys.path.insert(0, ".")
from apps.mtls_lab.make_certs import OUT  # noqa: E402
from scripts.livecheck import ROOT, Report, servers, wait_for_port  # noqa: E402

API = "http://localhost:8001"
MAILPIT = "http://localhost:8025/api/v1"
MTLS = "https://localhost:8443/internal/balance"
PASSWORD = "correct-horse-battery"


def newest_token(to: str) -> str:
    deadline = time.time() + 5
    while time.time() < deadline:
        messages = httpx.get(f"{MAILPIT}/search", params={"query": f"to:{to}"}).json()["messages"]
        if messages:
            detail = httpx.get(f"{MAILPIT}/message/{messages[0]['ID']}").json()
            return re.search(r"token=(\S+)", detail["Text"]).group(1)
        time.sleep(0.2)
    raise TimeoutError("No email arrived")


def mtls_request(certificate: str | None) -> str:
    context = ssl.create_default_context(cafile=str(OUT / "ca.pem"))
    if certificate:
        context.load_cert_chain(OUT / f"{certificate}.pem", OUT / f"{certificate}.key")
    try:
        return str(httpx.get(MTLS, verify=context, timeout=5).status_code)
    except httpx.HTTPError as exc:
        return type(exc).__name__


def main() -> None:
    report = Report()
    email = f"live-{secrets.token_hex(4)}@example.com"

    with servers(("apps.app1_jwt.main:app", 8001)):
        httpx.post(f"{API}/auth/register", json={"email": email, "password": PASSWORD})
        pair = httpx.post(
            f"{API}/auth/login", data={"username": email, "password": PASSWORD}
        ).json()
        headers = {"Authorization": f"Bearer {pair['access_token']}"}

        secret = httpx.post(f"{API}/mfa/totp/enroll", headers=headers).json()["secret"]
        confirmed = httpx.post(
            f"{API}/mfa/totp/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=headers
        )
        report.check("TOTP enrollment gives recovery codes", confirmed.status_code == 200)

        step = httpx.post(
            f"{API}/auth/login", data={"username": email, "password": PASSWORD}
        ).json()
        report.check("Password alone now gives no tokens", "access_token" not in step)
        finished = httpx.post(
            f"{API}/auth/login/mfa",
            json={"mfa_token": step["mfa_token"], "code": pyotp.TOTP(secret).now()},
        )
        report.check("A real TOTP code finishes the login", finished.status_code == 200)

        httpx.post(f"{API}/auth/magic/request", json={"email": email})
        token = newest_token(email)
        report.check("A real email arrives in Mailpit", len(token) > 20)
        used = httpx.post(f"{API}/auth/magic/verify", json={"token": token})
        report.check("The magic link signs in", used.status_code == 200)
        reused = httpx.post(f"{API}/auth/magic/verify", json={"token": token})
        report.check("The magic link cannot be reused", reused.status_code == 401)

        key = httpx.post(
            f"{API}/api-keys",
            json={"name": "Live", "scopes": ["reports:read"]},
            headers=headers,
        ).json()
        api = httpx.get(f"{API}/partner/reports", headers={"X-API-Key": key["key"]})
        report.check("An API key can call the partner route", api.status_code == 200)

    process = subprocess.Popen([sys.executable, "-m", "apps.mtls_lab.server"], cwd=ROOT)
    try:
        wait_for_port(8443)
        report.check("mTLS: a trusted client certificate works", mtls_request("client") == "200")
        report.check("mTLS: no certificate is refused", mtls_request(None) != "200")
        report.check("mTLS: another CA's certificate is refused", mtls_request("rogue") != "200")
    finally:
        process.terminate()
        process.wait(timeout=10)
    report.finish()


if __name__ == "__main__":
    main()
