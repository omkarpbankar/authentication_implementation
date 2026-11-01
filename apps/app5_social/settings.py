from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Add your own client IDs to apps/app5_social/.env. See SETUP.md."""

    model_config = SettingsConfigDict(env_prefix="APP5_", env_file="apps/app5_social/.env")

    base_url: str = "http://localhost:8005"
    redis_url: str = "redis://127.0.0.1:6380/5"
    session_ttl_seconds: int = 3600
    # How recently a user must have signed in before linking a new login method.
    reauth_window_seconds: int = 300
    # Encrypts stored provider tokens. Set a fixed value so tokens survive restarts.
    token_encryption_key: str = Fernet.generate_key().decode()

    keycloak_issuer: str = "http://localhost:8080/realms/course"
    keycloak_client_id: str = "app5-social"
    keycloak_client_secret: str = "app5-social-dev-secret"  # noqa: S105  A public practice value.

    google_client_id: str = ""
    google_client_secret: str = ""
    microsoft_client_id: str = ""
    microsoft_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""


settings = Settings()
