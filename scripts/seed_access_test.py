"""Load the application catalog into the App 8 test database. Used by CI.

Run:  uv run python scripts/seed_access_test.py
"""

import asyncio
import sys

sys.path.insert(0, ".")
from scripts.setup_access_db import seed  # noqa: E402

if __name__ == "__main__":
    asyncio.run(seed("access_test"))
