"""Every provider's token becomes one shared Identity, so later code never cares who issued it."""

from dataclasses import dataclass, field
from typing import Protocol

import jwt

from apps.app2_oidc.oidc import OidcProvider, TokenError
from apps.app4_cognito.tokens import CognitoTokenValidator


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    email: str = ""
    name: str = ""
    external_tenant: str = ""
    idp_roles: frozenset[str] = field(default_factory=frozenset)


class IssuerAdapter(Protocol):
    def matches(self, issuer: str) -> bool: ...

    async def identity(self, token: str) -> Identity: ...


class KeycloakAdapter:
    def __init__(self, provider: OidcProvider, audience: str) -> None:
        self.provider = provider
        self.audience = audience

    def matches(self, issuer: str) -> bool:
        return issuer == self.provider.issuer

    async def identity(self, token: str) -> Identity:
        claims = await self.provider.validate_access_token(token, self.audience)
        organizations = claims.get("organization") or []
        return Identity(
            issuer=claims["iss"],
            subject=claims["sub"],
            email=claims.get("email", ""),
            name=claims.get("name", claims.get("preferred_username", "")),
            # Keycloak 26.8 sends this as a list of organization aliases, such as ["acme"].
            external_tenant=organizations[0] if organizations else "",
            idp_roles=frozenset(claims.get("realm_access", {}).get("roles", [])),
        )


class EntraAdapter:
    def __init__(self, validator, issuer_prefix: str) -> None:
        self.validator = validator
        self.issuer_prefix = issuer_prefix

    def matches(self, issuer: str) -> bool:
        return bool(self.issuer_prefix) and issuer.startswith(self.issuer_prefix)

    async def identity(self, token: str) -> Identity:
        claims = await self.validator.validate(token)
        return Identity(
            issuer=claims["iss"],
            subject=f"{claims['tid']}:{claims.get('oid', claims['sub'])}",
            email=claims.get("preferred_username", ""),
            name=claims.get("name", ""),
            external_tenant=claims["tid"],
            idp_roles=frozenset(claims.get("roles", [])),
        )


class CognitoAdapter:
    def __init__(self, validator: CognitoTokenValidator) -> None:
        self.validator = validator

    def matches(self, issuer: str) -> bool:
        return issuer == self.validator.provider.issuer

    async def identity(self, token: str) -> Identity:
        claims = await self.validator.validate_access_token(token)
        return Identity(
            issuer=claims["iss"],
            subject=claims["sub"],
            email=claims.get("email", ""),
            # Cognito has no tenant concept, so this is a custom claim added by a Lambda.
            # Users must not be able to write to the attribute behind it.
            external_tenant=claims.get("tenant", ""),
            idp_roles=frozenset(claims.get("cognito:groups", [])),
        )


class TokenVerifier:
    def __init__(self, adapters: list[IssuerAdapter]) -> None:
        self.adapters = adapters

    async def identity(self, token: str) -> Identity:
        try:
            # Read without verifying, only to choose an adapter. The adapter then verifies it.
            issuer = jwt.decode(token, options={"verify_signature": False}).get("iss", "")
        except jwt.PyJWTError as exc:
            raise TokenError("Malformed token") from exc
        for adapter in self.adapters:
            if adapter.matches(issuer):
                return await adapter.identity(token)
        raise TokenError("Unknown issuer")
