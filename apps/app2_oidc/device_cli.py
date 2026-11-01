"""Sign in from a program with no browser, like a CLI or a TV app.

This is the Device Authorization flow. The program shows a link, you approve it in any
browser, and the program polls until the login server says it may continue.

Run:  uv run python -m apps.app2_oidc.device_cli
"""

import asyncio

import httpx

from apps.app2_oidc.oidc import OidcProvider
from apps.app2_oidc.settings import settings

CLIENT_ID = "app2-cli"
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


async def start(http: httpx.AsyncClient, metadata: dict) -> dict:
    response = await http.post(
        metadata["device_authorization_endpoint"],
        data={"client_id": CLIENT_ID, "scope": "openid profile"},
    )
    response.raise_for_status()
    return response.json()


async def poll(http: httpx.AsyncClient, metadata: dict, device: dict) -> dict:
    interval = device.get("interval", 5)
    while True:
        await asyncio.sleep(interval)
        response = await http.post(
            metadata["token_endpoint"],
            data={
                "grant_type": GRANT_TYPE,
                "device_code": device["device_code"],
                "client_id": CLIENT_ID,
            },
        )
        if response.status_code == 200:
            return response.json()
        error = response.json().get("error")
        if error == "slow_down":
            interval += 5
        elif error != "authorization_pending":
            raise RuntimeError(f"Device login failed: {error}")


async def main() -> None:
    provider = OidcProvider(settings.issuer)
    metadata = await provider.metadata()
    async with httpx.AsyncClient(timeout=10) as http:
        device = await start(http, metadata)
        print(f"Open {device['verification_uri_complete']} and approve the login.")
        tokens = await poll(http, metadata, device)
    print("Signed in. Access token received, ending in:", tokens["access_token"][-8:])


if __name__ == "__main__":
    asyncio.run(main())
