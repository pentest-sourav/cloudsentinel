from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class KinesisService:
    """
    Read-only Amazon Kinesis Data Streams discovery service.

    This service retrieves stream summaries and tags only.
    It never mutates Kinesis resources.
    """

    def __init__(self, session):
        self.session = session
        self.kinesis_client = create_aws_client(
            session,
            "kinesis",
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
                f"Kinesis {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Kinesis "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Kinesis "
            f"{operation}: {exc}"
        ) from exc

    def list_streams(self) -> list[str]:
        try:
            stream_names: list[str] = []
            next_token: str | None = None
            exclusive_start_stream_name: str | None = None

            while True:
                request: dict[str, Any] = {
                    "Limit": 100,
                }

                if next_token:
                    request["NextToken"] = next_token
                elif exclusive_start_stream_name:
                    request["ExclusiveStartStreamName"] = (
                        exclusive_start_stream_name
                    )

                response = self.kinesis_client.list_streams(
                    **request
                )

                names = response.get("StreamNames", [])

                if isinstance(names, list):
                    stream_names.extend(
                        name
                        for name in names
                        if isinstance(name, str) and name
                    )

                if response.get("HasMoreStreams") is not True:
                    break

                returned_token = response.get("NextToken")

                if isinstance(returned_token, str) and returned_token:
                    next_token = returned_token
                    exclusive_start_stream_name = None
                elif stream_names:
                    next_token = None
                    exclusive_start_stream_name = stream_names[-1]
                else:
                    break

            return stream_names

        except Exception as exc:
            self._raise_api_error(
                "stream discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_stream(
        self,
        stream_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.kinesis_client.describe_stream_summary(
                StreamName=stream_name,
            )

            summary = response.get(
                "StreamDescriptionSummary",
                {},
            )

            if not isinstance(summary, dict):
                return {}

            return summary

        except Exception as exc:
            self._raise_api_error(
                f"stream description for '{stream_name}'",
                exc,
            )
            raise AssertionError("unreachable")

    def list_stream_tags(
        self,
        stream_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.kinesis_client.list_tags_for_resource(
                ResourceARN=stream_arn,
            )

            tags = response.get("Tags", [])

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except Exception as exc:
            self._raise_api_error(
                f"tag discovery for '{stream_arn}'",
                exc,
            )
            raise AssertionError("unreachable")
