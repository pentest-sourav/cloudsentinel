from pydantic import model_validator
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
    cors_allowed_origins: str = ""
    app_environment: str = "development"
    audit_retention_days: int = 365
    max_request_body_bytes: int = 1_048_576
    trusted_proxy_ips: str = ""
    metrics_enabled: bool = False
    metrics_auth_token: str = ""

    rate_limit_window_seconds: int = 60
    rate_limit_auth_max_requests: int = 10
    rate_limit_scan_max_requests: int = 20
    rate_limit_global_max_requests: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


    @model_validator(mode="after")
    def validate_runtime_security(self):
        if self.max_request_body_bytes <= 0:
            raise ValueError("MAX_REQUEST_BODY_BYTES must be > 0")

        if self.audit_retention_days <= 0:
            raise ValueError("AUDIT_RETENTION_DAYS must be > 0")

        rate_limits = (
            self.rate_limit_window_seconds,
            self.rate_limit_auth_max_requests,
            self.rate_limit_scan_max_requests,
            self.rate_limit_global_max_requests,
        )
        if any(value <= 0 for value in rate_limits):
            raise ValueError("Rate limit settings must all be > 0")

        if "*" in self.cors_allowed_origins:
            raise ValueError(
                "Wildcard CORS origins are not allowed."
            )

        if self.app_environment.lower() == "production":
            if len(self.jwt_secret_key) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be at least 32 characters in production."
                )
            if self.metrics_enabled and len(self.metrics_auth_token) < 32:
                raise ValueError(
                    "METRICS_AUTH_TOKEN must be at least 32 characters "
                    "when metrics are enabled in production."
                )

        return self


settings = Settings()
