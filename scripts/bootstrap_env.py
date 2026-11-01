"""Create .env from .env.example, replacing each placeholder with a random secret."""

import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
TARGET = ROOT / ".env"
PLACEHOLDER = "change-me"


def main() -> None:
    if TARGET.exists():
        print(".env already exists, leaving it unchanged.")
        return

    lines = []
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.endswith(f"={PLACEHOLDER}"):
            name = line.split("=", 1)[0]
            line = f"{name}={secrets.token_urlsafe(24)}"
        lines.append(line)

    TARGET.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Created .env with random local secrets.")


if __name__ == "__main__":
    main()
