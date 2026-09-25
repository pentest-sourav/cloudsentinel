from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class CloudWatchService:
    """
    Read-only Amazon CloudWatch discovery service.

    Retrieves metric alarms and CloudWatch Logs log groups
    together with their security-relevant configuration.
    """

    def __init__(self, session):
        self.cloudwatch_client = create_aws_client(
            session,
            "cloudwatch",
        )

        self.logs_client = create_aws_client(
            session,
            "logs",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"CloudWatch {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during CloudWatch "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during CloudWatch "
            f"{operation}: {exc}"
        ) from exc

    def list_metric_alarms(
        self,
    ) -> list[dict[str, Any]]:
        alarms: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxRecords": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.cloudwatch_client
                    .describe_alarms(
                        **request
                    )
                )

                entries = response.get(
                    "MetricAlarms",
                    [],
                )

                if isinstance(entries, list):
                    alarms.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get(
                    "NextToken"
                )

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return alarms

        except Exception as exc:
            self._raise_api_error(
                "metric alarm discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_log_groups(
        self,
    ) -> list[dict[str, Any]]:
        log_groups: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "limit": 50,
                }

                if next_token:
                    request["nextToken"] = next_token

                response = (
                    self.logs_client
                    .describe_log_groups(
                        **request
                    )
                )

                entries = response.get(
                    "logGroups",
                    [],
                )

                if isinstance(entries, list):
                    log_groups.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get(
                    "nextToken"
                )

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return log_groups

        except Exception as exc:
            self._raise_api_error(
                "log group discovery",
                exc,
            )
            raise AssertionError("unreachable")
