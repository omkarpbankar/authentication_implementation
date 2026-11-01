"""The Access Service: the one place that decides who can use which application.

Run once:  uv run python scripts/setup_access_db.py
Run:       uv run uvicorn apps.app8_access.access_service.main:app --port 8010
"""

import secrets
import time
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import Depends, FastAPI, HTTPException, Response, status
from pydantic import BaseModel, Field
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from apps.app8_access.access_service import db as database
from apps.app8_access.access_service.admin import router as admin_router
from apps.app8_access.access_service.core import (
    ClaimsDep,
    RedisDep,
    application_by_id,
    load_facts,
    tenant_by_slug,
    upsert_user,
)
from apps.app8_access.access_service.db import audit, one
from apps.app8_access.access_service.decision import decide
from apps.app8_access.access_service.settings import settings
from apps.shared.hardening import apply_hardening
from apps.shared.metrics import ACCESS_DENIALS, metrics_response

app = FastAPI(title="App 8: Access Service")
apply_hardening(app)
app.include_router(admin_router)

REQUESTS_PER_HOUR = 5
# Which client belongs to which app almost never changes, so a short memory saves a query.
CLIENT_CACHE_SECONDS = 60
known_clients: dict[tuple[str, str], tuple[UUID, float]] = {}
DENIAL_LOG_WINDOW_SECONDS = 60


class Subject(BaseModel):
    type: str = "user"
    id: str
    properties: dict = {}


class Resource(BaseModel):
    type: str = "application"
    id: UUID


class Action(BaseModel):
    name: str = "use"


class EvaluationContext(BaseModel):
    tenant: str = ""
    feature: str = ""
    usage: int | None = None


class Evaluation(BaseModel):
    subject: Subject
    resource: Resource
    action: Action = Action()
    context: EvaluationContext = EvaluationContext()


class AccessRequest(BaseModel):
    subject: Subject
    tenant: str
    application_id: UUID
    requested_tier: str = "basic"
    note: str = Field(default="", max_length=500)


async def calling_application(claims: ClaimsDep) -> UUID:
    """Each app proves who it is with its own token, and may only ask about itself."""
    key = (claims["iss"], claims.get("azp", ""))
    cached = known_clients.get(key)
    if cached and cached[1] > time.monotonic():
        return cached[0]

    async with database.tenant_tx() as db:
        row = await one(
            db,
            """
            SELECT application_id FROM application_clients
            WHERE issuer = :i AND client_id = :c
            """,
            i=claims["iss"],
            c=claims.get("azp", ""),
        )
    if row is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Unknown application client")
    known_clients[key] = (row["application_id"], time.monotonic() + CLIENT_CACHE_SECONDS)
    return row["application_id"]


CallerDep = Annotated[UUID, Depends(calling_application)]


def require_same_application(caller: UUID, asked_about: UUID) -> None:
    # Without this, a compromised Notes app could map out who has access to Files.
    if caller != asked_about:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "An app may only ask about itself")


async def reference_for_denial(redis, tenant_id, user, application_id, reason: str) -> tuple:
    """A short reference ID for support. Repeat denials are grouped, to keep the log useful."""
    key = f"denied:{user['id']}:{application_id}:{reason}"
    reference = secrets.token_hex(4)
    try:
        existing = await redis.get(key)
        if existing:
            return existing, False
        await redis.set(key, reference, ex=DENIAL_LOG_WINDOW_SECONDS)
    except RedisError:
        pass
    return reference, True


@app.get("/health")
def health() -> dict[str, str]:
    """Is this process running? Used to decide whether to restart it."""
    return {"status": "ok"}


@app.get("/health/ready")
async def ready(redis: RedisDep) -> dict[str, str]:
    """Can this instance serve traffic? Redis is optional, as the cache only makes it faster."""
    try:
        async with database.tenant_tx() as db:
            await one(db, "SELECT 1 AS ok")
    except (OSError, SQLAlchemyError) as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Database unavailable") from exc
    try:
        await redis.ping()
        cache = "ok"
    except (OSError, RedisError):
        cache = "degraded"
    return {"status": "ok", "cache": cache}


@app.get("/metrics")
def metrics() -> Response:
    return metrics_response()


@app.post("/access/v1/evaluation")
async def evaluate(body: Evaluation, caller: CallerDep, redis: RedisDep) -> dict:
    """Follows the shape of the OpenID AuthZEN Authorization API 1.0."""
    require_same_application(caller, body.resource.id)

    async with database.tenant_tx() as db:
        tenant = await one(db, "SELECT * FROM tenants WHERE slug = :s", s=body.context.tenant)
        if tenant is None:
            # An unknown tenant learns nothing about which tenants exist.
            return {
                "decision": False,
                "context": {"reason_code": "NO_APP_ACCESS", "reference_id": ""},
            }

        structlog.contextvars.bind_contextvars(tenant_id=str(tenant["id"]))
        # One transaction from here on, so a decision uses a single connection.
        await database.set_tenant(db, tenant["id"])
        properties = body.subject.properties
        user = await upsert_user(
            db,
            tenant["id"],
            properties.get("issuer", settings.issuer),
            body.subject.id,
            properties.get("email", ""),
            properties.get("name", ""),
        )
        application = await application_by_id(db, body.resource.id)
        if application is None:
            return {
                "decision": False,
                "context": {"reason_code": "NO_APP_ACCESS", "reference_id": ""},
            }

        facts = await load_facts(db, user, tenant, application)
        result = decide(facts, body.context.feature, body.context.usage)

        if result.allowed:
            return {
                "decision": True,
                "context": {"tier": result.tier, "features": result.features},
            }

        ACCESS_DENIALS.labels(reason=result.reason_code).inc()
        reference, is_new = await reference_for_denial(
            redis, tenant["id"], user, application["id"], result.reason_code
        )
        if is_new:
            await audit(
                db,
                tenant["id"],
                user["id"],
                "access.denied",
                application["app_key"],
                reason=result.reason_code,
                reference_id=reference,
            )
    return {
        "decision": False,
        "context": {
            "reason_code": result.reason_code,
            "reference_id": reference,
            "tier": result.tier,
        },
    }


@app.post("/access/v1/requests", status_code=status.HTTP_202_ACCEPTED)
async def request_access(body: AccessRequest, caller: CallerDep, redis: RedisDep) -> dict[str, str]:
    require_same_application(caller, body.application_id)
    tenant = await tenant_by_slug(body.tenant)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown organization")

    try:
        key = f"requests:{body.subject.id}"
        count = await redis.incr(key)
        await redis.expire(key, 3600)
        if count > REQUESTS_PER_HOUR:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")
    except RedisError:
        pass

    properties = body.subject.properties
    try:
        async with database.tenant_tx(tenant["id"]) as db:
            user = await upsert_user(
                db,
                tenant["id"],
                properties.get("issuer", settings.issuer),
                body.subject.id,
                properties.get("email", ""),
                properties.get("name", ""),
            )
            await database.run(
                db,
                """
                INSERT INTO access_requests
                    (tenant_id, user_id, application_id, requested_tier, note)
                VALUES (:t, :u, :a, :r, :n)
                """,
                t=tenant["id"],
                u=user["id"],
                a=body.application_id,
                r=body.requested_tier,
                n=body.note,
            )
    except IntegrityError:
        # Already waiting. The same friendly answer, with no duplicate for the admin.
        return {"message": "Your request is already with your admin."}
    return {"message": "Your request has been sent to your admin."}
