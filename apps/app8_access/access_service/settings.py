from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP8_")

    database_url: str = (
        "postgresql+asyncpg://access_app:access-app-dev-password@127.0.0.1:5433/access"
    )
    redis_url: str = "redis://127.0.0.1:6380/8"
    issuer: str = "http://localhost:8080/realms/course"
    audience: str = "access-service"
    access_service_url: str = "http://localhost:8010"
    panel_url: str = "http://localhost:8011"
    # Sensitive admin actions need a sign-in this recent.
    reauth_seconds: int = 900
    # How long apps may reuse a decision. Changes normally apply sooner, through versioning.
    cache_ttl_seconds: int = 30


settings = Settings()
