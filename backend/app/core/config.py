from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CloudSentinel"
    app_version: str = "0.1.0"

    database_url: str = (
        "postgresql+psycopg://"
        "cloudsentinel:cloudsentinel_dev_password@localhost:15432/cloudsentinel"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
