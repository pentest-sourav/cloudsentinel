from typing import Any

from scanner.aws.services.kinesis import KinesisService


class KinesisDataCollector:
    """
    Normalize Amazon Kinesis Data Streams configuration
    for CloudSentinel security rules.
    """

    def __init__(self, service: KinesisService):
        self.service = service

        self._streams_cache: list[str] | None = None
        self._summary_cache: dict[
            str,
            dict[str, Any],
        ] = {}
        self._tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    def _get_streams(self) -> list[str]:
        if self._streams_cache is None:
            self._streams_cache = self.service.list_streams()

        return self._streams_cache

    def _get_summary(
        self,
        stream_name: str,
    ) -> dict[str, Any]:
        if stream_name not in self._summary_cache:
            self._summary_cache[stream_name] = (
                self.service.describe_stream(stream_name)
            )

        return self._summary_cache[stream_name]

    def _get_tags(
        self,
        stream_arn: str,
    ) -> list[dict[str, Any]]:
        if stream_arn not in self._tags_cache:
            self._tags_cache[stream_arn] = (
                self.service.list_stream_tags(stream_arn)
            )

        return self._tags_cache[stream_arn]

    def collect_streams(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for stream_name in self._get_streams():
            summary = self._get_summary(stream_name)

            stream_arn = summary.get("StreamARN")

            if not isinstance(stream_arn, str) or not stream_arn:
                continue

            normalized.append(
                {
                    "stream_name": stream_name,
                    "stream_arn": stream_arn,
                    "encryption_type": summary.get(
                        "EncryptionType"
                    ),
                    "key_id": summary.get("KeyId"),
                    "retention_period_hours": summary.get(
                        "RetentionPeriodHours"
                    ),
                    "stream_status": summary.get(
                        "StreamStatus"
                    ),
                    "tags": self._get_tags(stream_arn),
                }
            )

        return normalized
