from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CloudSentinel"
    app_version: str = "0.1.0"

    database_url: str
    redis_url: str

    scan_queue_stream: str = "cloudsentinel:scan_jobs"
    scan_queue_group: str = "cloudsentinel:scan_workers"
    scan_queue_max_retries: int = 3
    scan_queue_recovery_idle_ms: int = 30_000
    scan_queue_stale_scan_seconds: int = 120
    scan_queue_recovery_batch_size: int = 10
    scan_queue_read_block_ms: int = 5_000
    scan_queue_dead_letter_max_length: int = 10_000
    scan_queue_worker_heartbeat_seconds: int = 10
    scan_queue_worker_stale_seconds: int = 30

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    cors_allowed_origins: str = ""
    app_environment: str = "development"
    audit_retention_days: int = 365
    max_request_body_bytes: int = 1_048_576
    trusted_proxy_ips: str = ""
    security_headers_hsts_enabled: bool = False
    security_headers_hsts_max_age_seconds: int = 31_536_000
    metrics_enabled: bool = False
    metrics_auth_token: str = ""
    log_level: str = "INFO"
    log_format: str = "auto"

    rate_limit_window_seconds: int = 60
    rate_limit_auth_max_requests: int = 10
    rate_limit_scan_max_requests: int = 20
    rate_limit_global_max_requests: int = 300
    aws_sts_session_duration_seconds: int = 900
    aws_sdk_connect_timeout_seconds: int = 10
    aws_sdk_read_timeout_seconds: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


    @model_validator(mode="after")
    def validate_runtime_security(self):
        if self.max_request_body_bytes <= 0:
            raise ValueError("MAX_REQUEST_BODY_BYTES must be > 0")

        queue_settings = (
            self.scan_queue_max_retries,
            self.scan_queue_recovery_idle_ms,
            self.scan_queue_recovery_batch_size,
            self.scan_queue_read_block_ms,
            self.scan_queue_dead_letter_max_length,
            self.scan_queue_worker_heartbeat_seconds,
            self.scan_queue_worker_stale_seconds,
        )
        if any(value <= 0 for value in queue_settings):
            raise ValueError("Scan queue settings must all be > 0")

        if self.scan_queue_stale_scan_seconds <= (
            self.scan_queue_recovery_idle_ms / 1000
        ):
            raise ValueError(
                "SCAN_QUEUE_STALE_SCAN_SECONDS must be greater than "
                "SCAN_QUEUE_RECOVERY_IDLE_MS."
            )

        if self.audit_retention_days <= 0:
            raise ValueError("AUDIT_RETENTION_DAYS must be > 0")

        if self.security_headers_hsts_max_age_seconds <= 0:
            raise ValueError(
                "SECURITY_HEADERS_HSTS_MAX_AGE_SECONDS must be > 0"
            )

        if not 1 <= self.aws_sdk_connect_timeout_seconds <= 60:
            raise ValueError(
                "AWS_SDK_CONNECT_TIMEOUT_SECONDS must be between 1 and 60 seconds."
            )

        if not 1 <= self.aws_sdk_read_timeout_seconds <= 300:
            raise ValueError(
                "AWS_SDK_READ_TIMEOUT_SECONDS must be between 1 and 300 seconds."
            )

        if not 900 <= self.aws_sts_session_duration_seconds <= 43_200:
            raise ValueError(
                "AWS_STS_SESSION_DURATION_SECONDS must be between 900 and 43200 seconds."
            )

        rate_limits = (
            self.rate_limit_window_seconds,
            self.rate_limit_auth_max_requests,
            self.rate_limit_scan_max_requests,
            self.rate_limit_global_max_requests,
        )
        if any(value <= 0 for value in rate_limits):
            raise ValueError("Rate limit settings must all be > 0")

        if self.log_format.lower() not in {"auto", "json", "text"}:
            raise ValueError("LOG_FORMAT must be auto, json, or text")

        if self.log_level.upper() not in {
            "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
        }:
            raise ValueError("LOG_LEVEL must be a valid logging level")

        if "*" in self.cors_allowed_origins:
            raise ValueError(
                "Wildcard CORS origins are not allowed."
            )

        if self.jwt_access_token_expire_minutes <= 0:
            raise ValueError("JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be > 0")

        if self.app_environment.lower() == "production":
            if len(self.jwt_secret_key) < 32:
                raise ValueError(
                    "JWT_SECRET_KEY must be at least 32 characters in production."
                )
            if self.jwt_access_token_expire_minutes > 60:
                raise ValueError(
                    "JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be <= 60 in production."
                )
            if not self.security_headers_hsts_enabled:
                raise ValueError(
                    "SECURITY_HEADERS_HSTS_ENABLED must be true in production."
                )
            if self.log_format.lower() != "json":
                raise ValueError(
                    "LOG_FORMAT must be json in production."
                )
            if self.metrics_enabled and len(self.metrics_auth_token) < 32:
                raise ValueError(
                    "METRICS_AUTH_TOKEN must be at least 32 characters "
                    "when metrics are enabled in production."
                )

        return self


settings = Settings()
