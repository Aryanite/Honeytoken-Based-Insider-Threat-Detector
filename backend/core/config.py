from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Honeytoken-Based Insider Threat Detector"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"

    # Database: defaults to SQLite for local development
    # To use PostgreSQL, set: postgresql://user:password@host/dbname
    DATABASE_URL: str = "sqlite:///./honeytoken.db"

    # Beacon listener base URL used to construct canary tracking links
    BEACON_BASE_URL: str = "http://127.0.0.1:8000"

    # Security
    SECRET_KEY: str = "dev-secret-key-for-local-testing-only"
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
