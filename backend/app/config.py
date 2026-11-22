from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelX API"
    database_url: str = "sqlite:///./sentinelx.db"
    secret_key: str = "local-development-only-change-this-secret-key"
    access_token_expire_minutes: int = 60
    admin_email: str = "admin@sentinelx.local"
    admin_password: str = "ChangeMe123!"
    cors_origins: str = "http://localhost:5173"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
