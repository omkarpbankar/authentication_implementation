"""A pretend identity provider for tests: real RSA keys and real signed tokens, no network."""

import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


class FakeIdp:
    def __init__(
        self, issuer: str = "https://idp.test/realms/course", kid: str = "test-key"
    ) -> None:
        self.issuer = issuer
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def metadata(self) -> dict:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks",
            "end_session_endpoint": f"{self.issuer}/logout",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
        }

    def jwks(self) -> dict:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def token(self, audience: str | list[str], *, key=None, **claims) -> str:
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": audience,
            "sub": "user-123",
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            **claims,
        }
        return jwt.encode(payload, key or self.key, algorithm="RS256", headers={"kid": self.kid})
