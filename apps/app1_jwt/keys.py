"""Signing keys. Several keys can be live at once, which allows rotation with no sign-outs."""

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from jwt.algorithms import RSAAlgorithm


def key_id(public_key: RSAPublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:16]


class KeyRing:
    """New tokens use the newest key. Older keys stay until their tokens have expired."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.keys: dict[str, RSAPrivateKey] = {}
        self.active_kid = ""
        self._files: list[str] = []

    @classmethod
    def load_or_create(cls, directory: Path) -> "KeyRing":
        ring = cls(directory)
        ring.reload()
        if not ring.keys:
            ring.rotate()
        return ring

    def sync(self) -> None:
        """Notice keys added or removed by another process, such as an emergency rotation."""
        if sorted(path.name for path in self.directory.glob("*.pem")) != self._files:
            self.reload()

    def reload(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.keys = {}
        paths = sorted(self.directory.glob("*.pem"))
        self._files = [path.name for path in paths]
        # Sorted by name, and names contain the rotation number, so the last is the newest.
        for path in paths:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            kid = key_id(key.public_key())
            self.keys[kid] = key
            self.active_kid = kid

    def rotate(self) -> str:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        existing = [int(path.stem.split("-")[1]) for path in self.directory.glob("*.pem")]
        number = max(existing, default=0) + 1
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        (self.directory / f"key-{number:04d}.pem").write_bytes(pem)
        kid = key_id(key.public_key())
        self.keys[kid] = key
        self.active_kid = kid
        self._files = sorted(path.name for path in self.directory.glob("*.pem"))
        return kid

    def retire(self, kid: str) -> None:
        """Remove a key, for example after a leak. Tokens signed with it stop working."""
        for path in self.directory.glob("*.pem"):
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if key_id(key.public_key()) == kid:
                path.unlink()
        self.keys.pop(kid, None)
        self._files = sorted(path.name for path in self.directory.glob("*.pem"))

    @property
    def active_key(self) -> RSAPrivateKey:
        return self.keys[self.active_kid]

    def public_key(self, kid: str) -> RSAPublicKey | None:
        key = self.keys.get(kid)
        return key.public_key() if key else None

    def jwks(self) -> dict:
        """Public keys only. Publishing these is safe, as they can verify but never sign."""
        out = []
        for kid, key in self.keys.items():
            jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
            jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
            out.append(jwk)
        return {"keys": out}
