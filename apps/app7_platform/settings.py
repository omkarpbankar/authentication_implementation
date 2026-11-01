from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP7_", env_file="apps/app7_platform/.env")

    # The app connects as platform_app, which cannot bypass row-level security.
    database_url: str = "postgresql+asyncpg://platform_app:app-dev-password@127.0.0.1:5433/platform"
    support_database_url: str = (
        "postgresql+asyncpg://platform_support:support-dev-password@127.0.0.1:5433/platform"
    )
    redis_url: str = "redis://127.0.0.1:6380/7"
    issuer: str = "http://localhost:8008"
    audience: str = "app7-platform"
    access_ttl_seconds: int = 300
    keys_dir: Path = Path("apps/app7_platform/.keys")
    allowed_origins: list[str] = ["http://localhost:8008"]
    # One customer's traffic must not be able to slow down every other customer.
    tenant_requests_per_minute: int = 600

    keycloak_issuer: str = "http://localhost:8080/realms/course"
    entra_issuer_prefix: str = ""
    entra_audience: str = ""
    cognito_issuer: str = ""
    cognito_client_id: str = ""
    # What an IdP role becomes when someone joins a tenant through their company's login.
    idp_role_map: dict[str, str] = {"writer": "editor", "reader": "viewer"}


settings = Settings()
