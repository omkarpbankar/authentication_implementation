from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Values come from the CloudFormation stack outputs. See SETUP.md."""

    model_config = SettingsConfigDict(env_prefix="APP4_", env_file="apps/app4_cognito/.env")

    region: str = "ap-south-1"
    user_pool_id: str = "ap-south-1_example"
    client_id: str = "example-client-id"
    client_secret: str = ""
    m2m_client_id: str = "example-m2m-client-id"
    domain: str = "https://example.auth.ap-south-1.amazoncognito.com"
    base_url: str = "http://localhost:8004"
    redis_url: str = "redis://127.0.0.1:6380/4"

    @property
    def issuer(self) -> str:
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"


settings = Settings()
