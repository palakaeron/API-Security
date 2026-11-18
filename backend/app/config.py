from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings; secrets are supplied by the environment only."""

    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./api-security.db"
    session_secret: str | None = Field(default=None, repr=False)
    jwt_secret: str | None = Field(default=None, repr=False)
    jwt_access_token_minutes: int = Field(default=30, gt=0, le=1440)
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    controlled_target_hosts: str = "localhost,127.0.0.1,::1"
    controlled_target_cidrs: str = "127.0.0.0/8,::1/128"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
