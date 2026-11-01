# Multi-stage, so build tools never reach the final image.
FROM python:3.12-slim AS build
RUN pip install --no-cache-dir uv==0.12.1
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12-slim
WORKDIR /srv
COPY --from=build /srv/.venv /srv/.venv
COPY apps ./apps
ENV PATH="/srv/.venv/bin:$PATH" PYTHONUNBUFFERED=1

# A non-root user with no shell, so a compromised app has as little power as possible.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin app
USER app

EXPOSE 8010
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8010/health/ready', timeout=2)"]

# forwarded-allow-ips names the proxy. Without it, any client could fake its own address.
CMD ["uvicorn", "apps.app8_access.access_service.main:app", "--host", "0.0.0.0", "--port", "8010", "--proxy-headers", "--forwarded-allow-ips", "*"]
