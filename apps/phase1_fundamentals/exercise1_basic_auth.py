"""Exercise 1: HTTP Basic authentication.

Run:  uv run uvicorn apps.phase1_fundamentals.exercise1_basic_auth:app --port 8101
"""

import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pwdlib import PasswordHash

app = FastAPI(title="Phase 1, Exercise 1: HTTP Basic")
security = HTTPBasic()
password_hash = PasswordHash.recommended()

# The server keeps only the slow hash, so a stolen database does not reveal the password.
USERS = {"asha": password_hash.hash("correct-horse-battery")}

# Verifying against this for unknown users makes both failure paths take similar time.
DUMMY_HASH = password_hash.hash("not-a-real-account")


def current_user(credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> str:
    stored_hash = USERS.get(credentials.username, DUMMY_HASH)
    password_ok = password_hash.verify(credentials.password, stored_hash)
    # compare_digest avoids leaking how many characters matched through response timing.
    known_user = any(secrets.compare_digest(credentials.username, name) for name in USERS)

    if not (known_user and password_ok):
        # One error for both cases, so attackers cannot discover which usernames exist.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/public")
def public() -> dict[str, str]:
    return {"message": "Anyone can read this."}


@app.get("/secret")
def secret(username: Annotated[str, Depends(current_user)]) -> dict[str, str]:
    return {"message": f"Hello {username}, you are authenticated."}
