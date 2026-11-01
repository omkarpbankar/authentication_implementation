"""Reports. Standard adds CSV export, and Premium adds scheduled reports.

Run:  uv run uvicorn apps.app8_access.reports_app.main:app --port 8013
"""

import asyncio
import json
from dataclasses import asdict
from html import escape
from typing import Annotated

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, Response

from apps.app8_access.access_client.client import AccessDenied, User
from apps.app8_access.access_client.guard import AppConfig, Guard, page
from apps.app8_access.catalog import REPORTS_ID

app = FastAPI(title="Reports")
config = AppConfig("reports", "Reports", REPORTS_ID, "reports-app", 8013)
guard = Guard(app, config)

Access = tuple[User, dict]
SCHEDULE_KEY = "reports:schedules"
RECHECK_SECONDS = 5


@app.get("/", response_class=HTMLResponse)
async def home(
    access: Annotated[Access, Depends(guard.require_feature("reports.view"))],
) -> Response:
    user, context = access
    return page(
        "Reports",
        f"""
        <p>{escape(user.email)}, plan: <b>{escape(context["tier"].title())}</b></p>
        <p><a href="/reports/export.csv">Export CSV</a> |
           <a href="/reports/schedule">Schedule</a></p>
        <form method="post" action="/logout"><button>Sign out</button></form>
        """,
    )


@app.get("/reports/export.csv")
async def export_csv(
    access: Annotated[Access, Depends(guard.require_feature("reports.export_csv"))],
) -> dict:
    return {"filename": "report.csv"}


@app.get("/reports/schedule")
async def schedule(
    access: Annotated[Access, Depends(guard.require_feature("reports.schedule"))],
) -> dict:
    user, _ = access
    await guard.redis.sadd(SCHEDULE_KEY, json.dumps(asdict(user)))
    return {"message": "Scheduled"}


async def run_scheduled_reports() -> dict[str, int]:
    """A scheduled job has no request, so it checks the user's current access itself."""
    sent = skipped = 0
    for raw in await guard.redis.smembers(SCHEDULE_KEY):
        user = User(**json.loads(raw))
        try:
            await guard.access.check(user, "reports.schedule", fresh=True)
            sent += 1
        except AccessDenied:
            # Access may have ended after this was scheduled. Skip it, and stop repeating.
            await guard.redis.srem(SCHEDULE_KEY, raw)
            skipped += 1
    return {"sent": sent, "skipped": skipped}


@app.websocket("/reports/live")
async def live_updates(websocket: WebSocket) -> None:
    session = await guard.sessions.get(websocket.cookies.get(config.cookie))
    if session is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    user = User(**session["user"])
    await websocket.accept()
    try:
        while True:
            # A connection can outlive a grant, so it is rechecked for as long as it is open.
            await guard.access.check(user, "reports.view")
            await websocket.send_json({"update": "ok"})
            await asyncio.sleep(RECHECK_SECONDS)
    except AccessDenied:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    except WebSocketDisconnect:
        return
