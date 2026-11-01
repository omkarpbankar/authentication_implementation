from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Fill these in from your own app registrations. See SETUP.md."""

    model_config = SettingsConfigDict(env_prefix="APP3_", env_file="apps/app3_entra/.env")

    tenant_id: str = "00000000-0000-0000-0000-000000000000"
    web_client_id: str = "00000000-0000-0000-0000-000000000001"
    web_client_secret: str = ""
    api_client_id: str = "00000000-0000-0000-0000-000000000002"
    api_client_secret: str = ""
    # Extra customer tenants allowed to call the API, for multi-tenant apps.
    extra_allowed_tenants: list[str] = []
    base_url: str = "http://localhost:8003"
    redis_url: str = "redis://127.0.0.1:6380/3"
    login_host: str = "https://login.microsoftonline.com"
    graph_url: str = "https://graph.microsoft.com/v1.0/me"

    @property
    def authority(self) -> str:
        return f"{self.login_host}/{self.tenant_id}"

    @property
    def api_scope(self) -> str:
        return f"api://{self.api_client_id}/access_as_user"

    @property
    def allowed_tenants(self) -> set[str]:
        return {self.tenant_id, *self.extra_allowed_tenants}


settings = Settings()
