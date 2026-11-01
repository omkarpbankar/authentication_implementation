"""Add a new signing key. Old tokens keep working, since old keys stay available.

Run:             uv run python -m apps.app1_jwt.rotate_keys
After a leak:    uv run python -m apps.app1_jwt.rotate_keys --emergency

Emergency mode removes every older key, so all tokens they signed stop working at once.
"""

import sys

from apps.app1_jwt.keys import KeyRing
from apps.app1_jwt.settings import settings

if __name__ == "__main__":
    ring = KeyRing.load_or_create(settings.keys_dir)
    old_keys = list(ring.keys)
    print("New active key:", ring.rotate())
    if "--emergency" in sys.argv:
        for kid in old_keys:
            ring.retire(kid)
        print("Retired keys:", len(old_keys))
    print("Keys published:", len(ring.jwks()["keys"]))
