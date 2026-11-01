"""A background job with no user, using application permissions.

Run:  uv run python -m apps.app3_entra.daemon
"""

import httpx
import msal

from apps.app3_entra.settings import settings

API_URL = "http://localhost:8013/api/reports"


def main() -> dict:
    client = msal.ConfidentialClientApplication(
        settings.web_client_id,
        authority=settings.authority,
        client_credential=settings.web_client_secret,
    )
    # ".default" means every application permission an admin has already granted.
    result = client.acquire_token_for_client(scopes=[f"api://{settings.api_client_id}/.default"])
    if "access_token" not in result:
        raise RuntimeError(result.get("error_description", "Could not get a token"))
    response = httpx.get(API_URL, headers={"Authorization": f"Bearer {result['access_token']}"})
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    print(main())
