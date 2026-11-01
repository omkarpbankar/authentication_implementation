"""Notes. Basic gets 50 notes, Standard adds sharing, and Premium adds PDF export.

Run:  uv run uvicorn apps.app8_access.notes_app.main:app --port 8012
"""

from html import escape
from typing import Annotated

from fastapi import Depends, FastAPI, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from apps.app8_access.access_client.client import User
from apps.app8_access.access_client.guard import AppConfig, Guard, page
from apps.app8_access.catalog import NOTES_ID

app = FastAPI(title="Notes")
config = AppConfig("notes", "Notes", NOTES_ID, "notes-app", 8012)
guard = Guard(app, config)

Access = tuple[User, dict]


def notes_key(user: User) -> str:
    return f"notes:{user.tenant}:{user.subject}"


@app.get("/", response_class=HTMLResponse)
async def home(access: Annotated[Access, Depends(guard.require_feature("notes.read"))]) -> Response:
    user, context = access
    notes = await guard.redis.lrange(notes_key(user), 0, -1)
    items = "".join(f"<li>{escape(note)}</li>" for note in notes) or "<li>No notes yet</li>"
    return page(
        "Notes",
        f"""
        <p>{escape(user.email)}, plan: <b>{escape(context["tier"].title())}</b></p>
        <ul>{items}</ul>
        <form method="post" action="/notes"><input name="text"><button>Add</button></form>
        <p><a href="/notes/export">Export as PDF</a> | <a href="/notes/share">Share</a></p>
        <form method="post" action="/logout"><button>Sign out</button></form>
        """,
    )


@app.post("/notes")
async def create_note(
    user: Annotated[User, Depends(guard.current_user)],
    text: Annotated[str, Form(max_length=2000)],
) -> RedirectResponse:
    # A quota needs the live count, so this decision is never cached.
    usage = await guard.redis.llen(notes_key(user))
    await guard.access.check(user, "notes.create", usage=usage)
    await guard.redis.rpush(notes_key(user), text)
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/notes/share")
async def share(access: Annotated[Access, Depends(guard.require_feature("notes.share"))]) -> dict:
    return {"message": "Sharing is available on your plan."}


@app.get("/notes/export")
async def export(access: Annotated[Access, Depends(guard.require_feature("notes.export"))]) -> dict:
    user, _ = access
    document = await guard.redis.lrange(notes_key(user), 0, -1)
    # Exports can run for a long time, so access is checked again just before delivery.
    await guard.access.check(user, "notes.export", fresh=True)
    return {"filename": "notes.pdf", "notes": len(document)}
