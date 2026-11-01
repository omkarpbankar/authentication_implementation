"""Validating Cognito tokens, which differ from most providers in two important ways."""

import jwt

from apps.app2_oidc.oidc import CLOCK_SKEW_SECONDS, OidcProvider, TokenError


class CognitoTokenValidator:
    def __init__(self, provider: OidcProvider, allowed_client_ids: set[str]) -> None:
        self.provider = provider
        self.allowed_client_ids = allowed_client_ids

    async def _decode(self, token: str, audience: str | None) -> dict:
        try:
            kid = jwt.get_unverified_header(token).get("kid", "")
            key = await self.provider.signing_key(kid)
            return jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.provider.issuer,
                audience=audience,
                leeway=CLOCK_SKEW_SECONDS,
                # Access tokens have no "aud" claim, so that check runs by hand below.
                options={"verify_aud": audience is not None, "require": ["exp", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc

    async def validate_access_token(self, token: str) -> dict:
        claims = await self._decode(token, None)
        # Without this check, a token from any app client in the pool would pass.
        if claims.get("client_id") not in self.allowed_client_ids:
            raise TokenError("Token is for another app client")
        # Without this check, an ID token could be used to call the API.
        if claims.get("token_use") != "access":
            raise TokenError("Not an access token")
        return claims

    async def validate_id_token(self, token: str, client_id: str) -> dict:
        claims = await self._decode(token, client_id)
        if claims.get("token_use") != "id":
            raise TokenError("Not an ID token")
        return claims


def groups(claims: dict) -> set[str]:
    return set(claims.get("cognito:groups", []))


def scopes(claims: dict) -> set[str]:
    return set(claims.get("scope", "").split())
