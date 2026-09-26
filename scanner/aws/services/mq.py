from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class MQService:
    """
    Read-only Amazon MQ discovery service.

    Discovers brokers and retrieves the broker configuration required
    by CloudSentinel Amazon MQ security posture rules.
    """

    def __init__(self, session):
        self.mq_client = create_aws_client(session, "mq")

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
                f"AWS Amazon MQ {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Amazon MQ "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Amazon MQ "
            f"{operation}: {exc}"
        ) from exc

    def list_brokers(self) -> list[dict[str, Any]]:
        brokers: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.mq_client.list_brokers(
                    **request,
                )

                entries = response.get(
                    "BrokerSummaries",
                    [],
                )

                if isinstance(entries, list):
                    brokers.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return brokers

        except Exception as exc:
            self._raise_api_error(
                "broker discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_broker(
        self,
        broker_id: str,
    ) -> dict[str, Any]:
        if not isinstance(broker_id, str) or not broker_id:
            raise ValueError(
                "Amazon MQ broker ID must be a non-empty string"
            )

        try:
            response = self.mq_client.describe_broker(
                BrokerId=broker_id,
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                f"broker description for {broker_id}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_broker_details(self) -> list[dict[str, Any]]:
        details: list[dict[str, Any]] = []

        for summary in self.list_brokers():
            broker_id = summary.get("BrokerId")

            if (
                not isinstance(broker_id, str)
                or not broker_id
            ):
                continue

            detail = self.describe_broker(broker_id)

            if detail:
                details.append(detail)

        return details
