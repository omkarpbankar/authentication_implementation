from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP2_")

    issuer: str = "http://localhost:8080/realms/course"
    client_id: str = "app2-web"
    client_secret: str = "app2-web-dev-secret"  # noqa: S105  A public practice value.
    api_audience: str = "app2-api"
    base_url: str = "http://localhost:8002"
    redis_url: str = "redis://127.0.0.1:6380/2"
    session_ttl_seconds: int = 3600
    cookie_secure: bool = False


settings = Settings()
