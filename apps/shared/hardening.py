"""Protections every app needs: security headers, size limits, and safe structured logs."""

import logging
import os
import re
import secrets
import time
from collections.abc import MutableMapping

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

DEFAULT_CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
DEFAULT_MAX_BODY_BYTES = 1_048_576
SENSITIVE_KEYS = re.compile(
    r"password|passwd|secret|token|authorization|cookie|api[_-]?key|otp|code|assertion",
    re.IGNORECASE,
)
# Catches secrets that land inside a message, such as a JWT or a bearer header.
SENSITIVE_VALUES = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*|(?i:bearer)\s+\S+|ak_[0-9a-f]+_\S+")
REDACTED = "[redacted]"


def redact(_logger, _method, event: MutableMapping) -> MutableMapping:
    """The last step before a log line is written, so secrets never reach the logs."""
    for key, value in list(event.items()):
        if SENSITIVE_KEYS.search(key):
            event[key] = REDACTED
        elif isinstance(value, str):
            event[key] = SENSITIVE_VALUES.sub(REDACTED, value)
    return event


structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        redact,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO"))
    ),
)
log = structlog.get_logger()


def apply_hardening(
    app: FastAPI,
    *,
    csp: str = DEFAULT_CSP,
    hsts: bool = False,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> None:
    """Set hsts to True only behind HTTPS, as browsers remember it for a long time."""

    @app.middleware("http")
    async def harden(request: Request, call_next) -> Response:
        request_id = secrets.token_hex(8)
        structlog.contextvars.bind_contextvars(request_id=request_id)

        declared = request.headers.get("content-length", "0")
        if declared.isdigit() and int(declared) > max_body_bytes:
            return JSONResponse({"detail": "Request is too large"}, status_code=413)

        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = csp
        # Stops the back button from showing a protected page after sign-out.
        response.headers["Cache-Control"] = "no-store"
        if hsts:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # The path only, because query strings can carry state values and link tokens.
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
        )
        structlog.contextvars.clear_contextvars()
        return response
