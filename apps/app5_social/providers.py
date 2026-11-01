"""One shape for every login provider. Adding an OIDC provider is one entry in build_registry."""

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlencode

import httpx

from apps.app2_oidc.oidc import OidcProvider, TokenError
from apps.app5_social.settings import Settings

GOOGLE_ISSUER = "https://accounts.google.com"
# Microsoft's fixed tenant ID for personal accounts, such as outlook.com addresses.
MICROSOFT_ISSUER = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105
GITHUB_API = "https://api.github.com"


@dataclass(frozen=True)
class Profile:
    provider: str
    subject: str  # Stable. Emails and names can change, so this is the real identity.
    email: str
    email_verified: bool
    name: str


class Adapter(Protocol):
    name: str

    async def authorize_url(
        self, redirect_uri: str, state: str, nonce: str, challenge: str, extra: dict | None = None
    ) -> str: ...

    async def finish(
        self, code: str, verifier: str, nonce: str, redirect_uri: str
    ) -> tuple[Profile, dict]: ...


class OidcAdapter:
    def __init__(
        self,
        name: str,
        issuer: str,
        client_id: str,
        client_secret: str,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.provider = OidcProvider(issuer, http)

    async def authorize_url(
        self, redirect_uri: str, state: str, nonce: str, challenge: str, extra: dict | None = None
    ) -> str:
        extra = dict(extra or {})
        scope = extra.pop("scope", "openid email profile")
        url = await self.provider.authorization_url(
            self.client_id, redirect_uri, state, nonce, challenge, scope
        )
        return f"{url}&{urlencode(extra)}" if extra else url

    async def finish(
        self, code: str, verifier: str, nonce: str, redirect_uri: str
    ) -> tuple[Profile, dict]:
        tokens = await self.provider.exchange_code(
            code, verifier, self.client_id, self.client_secret, redirect_uri
        )
        claims = await self.provider.validate_id_token(tokens["id_token"], self.client_id, nonce)
        return (
            Profile(
                provider=self.name,
                subject=claims["sub"],
                email=claims.get("email", "").lower(),
                email_verified=claims.get("email_verified") is True,
                name=claims.get("name", claims.get("preferred_username", "")),
            ),
            tokens,
        )

    async def refresh(self, refresh_token: str) -> dict:
        return await self.provider.refresh(refresh_token, self.client_id, self.client_secret)


class GitHubAdapter:
    """GitHub login is OAuth, not OIDC. There is no ID token, so the profile comes from its API."""

    name = "github"

    def __init__(
        self, client_id: str, client_secret: str, http: httpx.AsyncClient | None = None
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = http or httpx.AsyncClient(timeout=10)

    async def authorize_url(
        self, redirect_uri: str, state: str, nonce: str, challenge: str, extra: dict | None = None
    ) -> str:
        query = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{GITHUB_AUTHORIZE_URL}?{urlencode(query)}"

    async def finish(
        self, code: str, verifier: str, nonce: str, redirect_uri: str
    ) -> tuple[Profile, dict]:
        response = await self.http.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            },
        )
        tokens = response.json()
        if "access_token" not in tokens:
            raise TokenError("GitHub refused the code")

        headers = {
            "Authorization": f"Bearer {tokens['access_token']}",
            "Accept": "application/vnd.github+json",
        }
        user = (await self.http.get(f"{GITHUB_API}/user", headers=headers)).json()
        # Users can hide their public email, so ask for the verified list directly.
        emails = (await self.http.get(f"{GITHUB_API}/user/emails", headers=headers)).json()
        primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
        return (
            Profile(
                provider=self.name,
                subject=str(user["id"]),  # The login name can change. The numeric ID cannot.
                email=(primary or {}).get("email", "").lower(),
                email_verified=primary is not None,
                name=user.get("name") or user.get("login", ""),
            ),
            tokens,
        )


def build_registry(settings: Settings) -> dict[str, Adapter]:
    """Providers appear only once they are configured."""
    registry: dict[str, Adapter] = {}
    oidc_providers = [
        (
            "keycloak",
            settings.keycloak_issuer,
            settings.keycloak_client_id,
            settings.keycloak_client_secret,
        ),
        ("google", GOOGLE_ISSUER, settings.google_client_id, settings.google_client_secret),
        (
            "microsoft",
            MICROSOFT_ISSUER,
            settings.microsoft_client_id,
            settings.microsoft_client_secret,
        ),
    ]
    for name, issuer, client_id, client_secret in oidc_providers:
        if client_id:
            registry[name] = OidcAdapter(name, issuer, client_id, client_secret)
    if settings.github_client_id:
        registry["github"] = GitHubAdapter(settings.github_client_id, settings.github_client_secret)
    return registry
