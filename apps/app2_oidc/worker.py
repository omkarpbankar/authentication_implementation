"""A background worker. There is no user here, so it signs in as itself.

This is the Client Credentials flow, used for service-to-service calls.
Run:  uv run python -m apps.app2_oidc.worker
"""

import asyncio

import httpx

from apps.app2_oidc.oidc import OidcProvider
from apps.app2_oidc.settings import settings

API_URL = "http://localhost:8022/api/whoami"
CLIENT_ID = "app2-worker"
CLIENT_SECRET = "app2-worker-dev-secret"  # noqa: S105  A public practice value.


async def main() -> dict:
    provider = OidcProvider(settings.issuer)
    metadata = await provider.metadata()
    async with httpx.AsyncClient(timeout=10) as http:
        response = await http.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        api_response = await http.get(API_URL, headers={"Authorization": f"Bearer {token}"})
        api_response.raise_for_status()
        return api_response.json()


if __name__ == "__main__":
    print(asyncio.run(main()))
