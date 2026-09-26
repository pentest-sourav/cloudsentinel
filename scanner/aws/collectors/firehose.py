from typing import Any

from scanner.aws.services.firehose import FirehoseService


class FirehoseDataCollector:
    """
    Normalize AWS Data Firehose configuration for security rules.

    API responses are collected once and cached for the lifetime
    of the collector.
    """

    def __init__(self, service: FirehoseService):
        self.service = service
        self._delivery_streams_cache: list[
            dict[str, Any]
        ] | None = None

    def collect_delivery_streams(
        self,
    ) -> list[dict[str, Any]]:
        if self._delivery_streams_cache is not None:
            return self._delivery_streams_cache

        normalized: list[dict[str, Any]] = []

        for stream_name in self.service.list_delivery_streams():
            description = self.service.describe_delivery_stream(
                stream_name
            )

            encryption = description.get(
                "DeliveryStreamEncryptionConfiguration"
            ) or {}

            normalized.append(
                {
                    "delivery_stream_name": description.get(
                        "DeliveryStreamName",
                        stream_name,
                    ),
                    "delivery_stream_arn": description.get(
                        "DeliveryStreamARN"
                    ),
                    "delivery_stream_status": description.get(
                        "DeliveryStreamStatus"
                    ),
                    "delivery_stream_type": description.get(
                        "DeliveryStreamType"
                    ),
                    "encryption_status": encryption.get(
                        "Status"
                    ),
                    "encryption_key_type": encryption.get(
                        "KeyType"
                    ),
                    "encryption_key_arn": encryption.get(
                        "KeyARN"
                    ),
                }
            )

        self._delivery_streams_cache = normalized
        return self._delivery_streams_cache
