"""Exercise 3: a small practice bank with one vulnerable route and one protected route.

Run the bank:
    uv run uvicorn apps.phase1_fundamentals.csrf_lab.bank:app --host localhost --port 8103

This lab is for your own machine only. Open it at http://localhost:8103, because the
attacker page runs on 127.0.0.1, and browsers treat those as two different sites.
"""

import secrets
from dataclasses import dataclass, field
from html import escape
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

COOKIE_NAME = "bank_session"
START_BALANCE = 1000


@dataclass
class Session:
    username: str
    # One random token per session. The attacker's page has no way to read it.
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))


app = FastAPI(title="Phase 1, Exercise 3: CSRF lab")
sessions: dict[str, Session] = {}
balances: dict[str, int] = {}
history: list[str] = []


def current_session(session_id: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None) -> Session:
    session = sessions.get(session_id or "")
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    return session


SessionDep = Annotated[Session, Depends(current_session)]


def move_money(session: Session, to: str, amount: int, route: str) -> None:
    balances[session.username] -= amount
    history.append(f"{route}: sent {amount} to {to}")


@app.post("/login")
def login(username: Annotated[str, Form()]) -> Response:
    # Practice login with no password, so the lab stays focused on CSRF.
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = Session(username=username)
    balances.setdefault(username, START_BALANCE)
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(COOKIE_NAME, session_id, httponly=True, samesite="lax")
    return response


@app.post("/reset")
def reset(session: SessionDep) -> Response:
    balances[session.username] = START_BALANCE
    history.clear()
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/vulnerable/transfer")
def vulnerable_transfer(session: SessionDep, to: str, amount: int) -> dict[str, str]:
    # VULNERABLE, for the lab. A GET that changes data can be triggered by a link, and
    # SameSite=Lax still sends cookies on a top-level GET navigation from another site.
    move_money(session, to, amount, "vulnerable GET")
    return {"message": f"Sent {amount} to {to}"}


@app.post("/vulnerable/transfer-post")
def vulnerable_transfer_post(
    session: SessionDep,
    to: Annotated[str, Form()],
    amount: Annotated[int, Form()],
) -> dict[str, str]:
    # Has no CSRF token. SameSite=Lax is the only thing protecting this route.
    move_money(session, to, amount, "vulnerable POST")
    return {"message": f"Sent {amount} to {to}"}


@app.post("/safe/transfer")
def safe_transfer(
    session: SessionDep,
    to: Annotated[str, Form()],
    amount: Annotated[int, Form()],
    csrf_token: Annotated[str, Form()] = "",
) -> dict[str, str]:
    # The fix: uses POST, and requires a token that only this bank's own page could include.
    if not secrets.compare_digest(csrf_token, session.csrf_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")
    move_money(session, to, amount, "safe POST")
    return {"message": f"Sent {amount} to {to}"}


@app.get("/", response_class=HTMLResponse)
def home(session_id: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None) -> str:
    session = sessions.get(session_id or "")
    if session is None:
        return """
        <h1>Practice Bank</h1>
        <form method="post" action="/login">
          <input name="username" value="asha">
          <button>Sign in</button>
        </form>
        """

    rows = "".join(f"<li>{escape(item)}</li>" for item in history) or "<li>No transfers yet</li>"
    return f"""
    <h1>Practice Bank</h1>
    <p>Signed in as <b>{escape(session.username)}</b>.
       Balance: <b id="balance">{balances[session.username]}</b></p>
    <h2>Transfer (protected)</h2>
    <form method="post" action="/safe/transfer">
      <input type="hidden" name="csrf_token" value="{session.csrf_token}">
      <input name="to" placeholder="to" value="friend">
      <input name="amount" type="number" value="10">
      <button>Send</button>
    </form>
    <h2>History</h2>
    <ul id="history">{rows}</ul>
    <form method="post" action="/reset"><button>Reset lab</button></form>
    """
