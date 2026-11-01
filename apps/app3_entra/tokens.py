"""Validating tokens issued by Microsoft Entra ID."""

import httpx
import jwt

from apps.app2_oidc.oidc import OidcProvider, TokenError


class EntraTokenValidator:
    def __init__(
        self,
        login_host: str,
        allowed_tenants: set[str],
        audiences: list[str],
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.login_host = login_host
        self.allowed_tenants = allowed_tenants
        self.audiences = audiences
        self.http = http
        self._providers: dict[str, OidcProvider] = {}

    def _provider_for(self, tenant_id: str) -> OidcProvider:
        if tenant_id not in self._providers:
            issuer = f"{self.login_host}/{tenant_id}/v2.0"
            self._providers[tenant_id] = OidcProvider(issuer, self.http)
        return self._providers[tenant_id]

    async def validate(self, token: str) -> dict:
        try:
            # Read without verifying, only to choose which tenant's keys to use. Nothing
            # from this result is trusted until the signature check below has passed.
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise TokenError("Malformed token") from exc

        tenant_id = str(unverified.get("tid", ""))
        # Any Microsoft organization can get a valid token, so the tenant must be on our list.
        if tenant_id not in self.allowed_tenants:
            raise TokenError("Tenant is not allowed")

        claims = await self._provider_for(tenant_id).validate_access_token(token, self.audiences)
        # Without accessTokenAcceptedVersion 2 in the manifest, Entra issues v1 tokens.
        if claims.get("ver") != "2.0":
            raise TokenError("Expected a v2.0 token")
        return claims


def scopes(claims: dict) -> set[str]:
    """Delegated permissions: what the app may do for the signed-in user."""
    return set(claims.get("scp", "").split())


def app_roles(claims: dict) -> set[str]:
    """App roles, for both users and daemons. Daemons have no scp claim."""
    return set(claims.get("roles", []))


def is_app_only(claims: dict) -> bool:
    return "scp" not in claims and claims.get("idtyp") == "app"


def groups_are_incomplete(claims: dict) -> bool:
    """Users in too many groups get a pointer to Graph, instead of the groups claim."""
    return "groups" in claims.get("_claim_names", {}) or "hasgroups" in claims
