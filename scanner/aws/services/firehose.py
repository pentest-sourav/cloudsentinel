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
            paginator = self.firehose_client.get_paginator(
                "list_delivery_streams"
            )

            streams: list[str] = []

            for page in paginator.paginate():
                streams.extend(
                    page.get("DeliveryStreamNames", [])
                )

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
