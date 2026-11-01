from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP6_")

    issuer: str = "http://localhost:8080/realms/course"
    client_id: str = "app6-oidc"
    client_secret: str = "app6-oidc-dev-secret"  # noqa: S105  A public practice value.
    base_url: str = "http://localhost:8006"
    redis_url: str = "redis://127.0.0.1:6380/6"
    scim_token: str = "scim-dev-token"  # noqa: S105  A public practice value.
    # Which identity provider serves each company's email domain.
    sso_domains: dict[str, str] = {"acme.example": "keycloak", "globex.example": "keycloak"}


settings = Settings()
