from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CloudSentinel"
    app_version: str = "0.1.0"

    database_url: str
    redis_url: str

    scan_queue_stream: str = "cloudsentinel:scan_jobs"
    scan_queue_group: str = "cloudsentinel:scan_workers"

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
