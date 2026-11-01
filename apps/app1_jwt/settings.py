from pathlib import Path

from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APP1_")

    redis_url: str = "redis://127.0.0.1:6380/1"
    issuer: str = "http://localhost:8001"
    audience: str = "app1-api"
    access_ttl_seconds: int = 600
    refresh_ttl_seconds: int = 1_209_600
    keys_dir: Path = Path("apps/app1_jwt/.keys")
    # Encrypts TOTP secrets at rest. Set a fixed value so MFA survives restarts.
    mfa_encryption_key: str = Fernet.generate_key().decode()
    # Passkeys are tied to this domain, which is why they resist phishing.
    rp_id: str = "localhost"
    origin: str = "http://localhost:8001"
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 1025
    mail_from: str = "no-reply@course.example"


settings = Settings()
