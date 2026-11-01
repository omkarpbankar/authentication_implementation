"""Numbers for dashboards and alerts. The alert rules are in deploy/alerts.yml."""

from fastapi import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest

ACCESS_DENIALS = Counter("access_denials_total", "Access decisions that were denied", ["reason"])


def metrics_response() -> Response:
    """Keep this path private. In production the proxy does not forward it."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
