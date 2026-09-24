"""Core configuration and settings for CAGE."""

import os

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict

    class Settings(BaseSettings):
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore",
        )

        app_name: str = "CAGE - Causal Authorization Engine"
        version: str = "0.1.0"
        environment: str = os.getenv("CAGE_ENV", "development")
        debug: bool = os.getenv("CAGE_DEBUG", "true").lower() in ("true", "1", "yes")

        host: str = os.getenv("CAGE_HOST", "0.0.0.0")
        port: int = int(os.getenv("CAGE_PORT", "8000"))

        database_url: str = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://cage_user:cage_password@localhost:5432/cage_db",
        )
        redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        opa_url: str = os.getenv("OPA_URL", "http://localhost:8181")

        secret_key: str = os.getenv("CAGE_SECRET_KEY", "dev-secret-key-change-in-production")
        api_key: str | None = os.getenv("CAGE_API_KEY", "cage_dev_test_api_key")

except ImportError:
    from pydantic import BaseModel

    class Settings(BaseModel):  # type: ignore[no-redef]
        app_name: str = "CAGE - Causal Authorization Engine"
        version: str = "0.1.0"
        environment: str = os.getenv("CAGE_ENV", "development")
        debug: bool = os.getenv("CAGE_DEBUG", "true").lower() in ("true", "1", "yes")

        host: str = os.getenv("CAGE_HOST", "0.0.0.0")
        port: int = int(os.getenv("CAGE_PORT", "8000"))

        database_url: str = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://cage_user:cage_password@localhost:5432/cage_db",
        )
        redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        opa_url: str = os.getenv("OPA_URL", "http://localhost:8181")

        secret_key: str = os.getenv("CAGE_SECRET_KEY", "dev-secret-key-change-in-production")
        api_key: str | None = os.getenv("CAGE_API_KEY", "cage_dev_test_api_key")


settings = Settings()
