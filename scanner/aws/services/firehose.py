from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class FirehoseService:
    """
    Read-only AWS Data Firehose discovery service.

    AWS API collection is isolated from CloudSentinel rule evaluation.
    """

    def __init__(self, session):
        self.session = session
        self.firehose_client = create_aws_client(
            session,
            "firehose",
        )

    def list_delivery_streams(self) -> list[str]:
        try:
            streams: list[str] = []
            start_name: str | None = None

            while True:
                kwargs: dict[str, Any] = {
                    "Limit": 100,
                }

                if start_name:
                    kwargs["ExclusiveStartDeliveryStreamName"] = start_name

                response = self.firehose_client.list_delivery_streams(
                    **kwargs
                )

                names = response.get(
                    "DeliveryStreamNames",
                    [],
                )

                if isinstance(names, list):
                    streams.extend(
                        name
                        for name in names
                        if isinstance(name, str)
                    )

                has_more = response.get(
                    "HasMoreDeliveryStreams",
                    False,
                )

                if not has_more:
                    break

                if not names:
                    break

                last_name = names[-1]

                if (
                    not isinstance(last_name, str)
                    or not last_name
                    or last_name == start_name
                ):
                    break

                start_name = last_name

            return streams

        except (ClientError, BotoCoreError) as exc:
            if isinstance(exc, ClientError):
                error = exc.response.get("Error", {})
                code = error.get("Code", "UnknownError")
                message = error.get(
                    "Message",
                    "AWS request failed",
                )

                raise RuntimeError(
                    "Firehose delivery-stream discovery failed: "
                    f"{code}: {message}"
                ) from exc

            raise RuntimeError(
                "AWS SDK error during Firehose "
                f"delivery-stream discovery: {exc}"
            ) from exc

    def describe_delivery_stream(
        self,
        delivery_stream_name: str,
    ) -> dict[str, Any]:
        if not delivery_stream_name:
            return {}

        try:
            response = self.firehose_client.describe_delivery_stream(
                DeliveryStreamName=delivery_stream_name,
            )

            return response.get(
                "DeliveryStreamDescription",
                {},
            )

        except (ClientError, BotoCoreError) as exc:
            if isinstance(exc, ClientError):
                error = exc.response.get("Error", {})
                code = error.get("Code", "UnknownError")
                message = error.get(
                    "Message",
                    "AWS request failed",
                )
                raise RuntimeError(
                    "Firehose delivery-stream description failed "
                    f"for {delivery_stream_name}: "
                    f"{code}: {message}"
                ) from exc

            raise RuntimeError(
                "AWS SDK error during Firehose delivery-stream "
                f"description for {delivery_stream_name}: {exc}"
            ) from exc
