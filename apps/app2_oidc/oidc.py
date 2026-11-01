"""Talking to an OpenID Connect provider, written out by hand so each step is visible."""

import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt

ALGORITHMS = ["RS256"]
JWKS_REFRESH_LIMIT_SECONDS = 30
# Servers never agree on the time exactly. With no allowance, a token can look like it was
# issued in the future, and a real user gets a random login failure.
CLOCK_SKEW_SECONDS = 30
LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class TokenError(Exception):
    pass


def new_pkce_pair() -> tuple[str, str]:
    """The verifier stays secret. Only its hash travels through the browser."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class OidcProvider:
    def __init__(self, issuer: str, http: httpx.AsyncClient | None = None) -> None:
        self.issuer = issuer
        self.http = http or httpx.AsyncClient(timeout=10)
        self._metadata: dict | None = None
        self._keys: dict[str, dict] = {}
        self._parsed_keys: dict[str, object] = {}
        self._keys_fetched_at = 0.0

    async def metadata(self) -> dict:
        if self._metadata is None:
            url = f"{self.issuer}/.well-known/openid-configuration"
            response = await self.http.get(url)
            response.raise_for_status()
            metadata = response.json()
            # A mismatch here would mean talking to the wrong server.
            if metadata["issuer"] != self.issuer:
                raise TokenError("Provider issuer does not match configuration")
            self._metadata = metadata
        return self._metadata

    async def _refresh_keys(self) -> None:
        # Limited, so junk tokens with random key IDs cannot make us hammer the provider.
        if time.time() - self._keys_fetched_at < JWKS_REFRESH_LIMIT_SECONDS:
            return
        metadata = await self.metadata()
        response = await self.http.get(metadata["jwks_uri"])
        response.raise_for_status()
        self._keys = {key["kid"]: key for key in response.json()["keys"]}
        self._parsed_keys = {}
        self._keys_fetched_at = time.time()

    async def signing_key(self, kid: str):
        if kid not in self._keys:
            await self._refresh_keys()
        if kid not in self._keys:
            raise TokenError("Unknown signing key")
        # Building a key object is slow, and this runs on every request.
        if kid not in self._parsed_keys:
            self._parsed_keys[kid] = jwt.PyJWK(self._keys[kid]).key
        return self._parsed_keys[kid]

    async def authorization_url(
        self, client_id: str, redirect_uri: str, state: str, nonce: str, challenge: str, scope: str
    ) -> str:
        metadata = await self.metadata()
        query = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{metadata['authorization_endpoint']}?{urlencode(query)}"

    async def _token_request(self, data: dict) -> dict:
        metadata = await self.metadata()
        response = await self.http.post(metadata["token_endpoint"], data=data)
        if response.status_code != 200:
            raise TokenError("Token request was refused")
        return response.json()

    async def exchange_code(
        self, code: str, verifier: str, client_id: str, client_secret: str, redirect_uri: str
    ) -> dict:
        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        )

    async def refresh(self, refresh_token: str, client_id: str, client_secret: str) -> dict:
        return await self._token_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        )

    async def _decode(self, token: str, audience: str | list[str]) -> dict:
        try:
            kid = jwt.get_unverified_header(token).get("kid", "")
            key = await self.signing_key(kid)
            return jwt.decode(
                token,
                key,
                algorithms=ALGORITHMS,
                audience=audience,
                issuer=self.issuer,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(str(exc)) from exc

    async def validate_id_token(self, token: str, client_id: str, nonce: str) -> dict:
        claims = await self._decode(token, client_id)
        # The nonce ties this ID token to this login attempt, which stops replay.
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise TokenError("Nonce mismatch")
        return claims

    async def validate_access_token(self, token: str, audience: str | list[str]) -> dict:
        return await self._decode(token, audience)

    async def validate_logout_token(self, token: str, client_id: str) -> dict:
        claims = await self._decode(token, client_id)
        # The events claim stops any other kind of token from being replayed as a logout.
        if LOGOUT_EVENT not in claims.get("events", {}):
            raise TokenError("Not a logout token")
        if "nonce" in claims:
            raise TokenError("Logout tokens must not contain a nonce")
        return claims
