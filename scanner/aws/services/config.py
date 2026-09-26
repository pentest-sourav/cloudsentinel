from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class ConfigService:
    """Read-only AWS Config discovery service."""

    def __init__(self, session):
        self.session = session
        self.config_client = create_aws_client(
            session,
            "config",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS Config {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AWS Config "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AWS Config "
            f"{operation}: {exc}"
        ) from exc

    def describe_configuration_recorders(
        self,
    ) -> list[dict[str, Any]]:
        try:
            response = (
                self.config_client.describe_configuration_recorders()
            )

            return response.get(
                "ConfigurationRecorders",
                [],
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "describe_configuration_recorders",
                exc,
            )

        return []

    def describe_configuration_recorder_status(
        self,
    ) -> list[dict[str, Any]]:
        try:
            response = (
                self.config_client
                .describe_configuration_recorder_status()
            )

            return response.get(
                "ConfigurationRecordersStatus",
                [],
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "describe_configuration_recorder_status",
                exc,
            )

        return []
