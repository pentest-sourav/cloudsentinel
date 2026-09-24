from typing import Any

from scanner.aws.services.sqs import SQSService


class SQSDataCollector:
    """
    Normalize AWS SQS queue configuration for CloudSentinel rules.
    """

    def __init__(self, service: SQSService):
        self.service = service

        self._queues_cache: list[str] | None = None
        self._attributes_cache: dict[str, dict[str, Any]] = {}
        self._policy_cache: dict[str, dict[str, Any]] = {}
        self._tags_cache: dict[str, list[dict[str, Any]]] = {}

    def _get_queues(self) -> list[str]:
        if self._queues_cache is None:
            self._queues_cache = self.service.list_queues()

        return self._queues_cache

    def _get_attributes(
        self,
        queue_url: str,
    ) -> dict[str, Any]:
        if queue_url not in self._attributes_cache:
            self._attributes_cache[queue_url] = (
                self.service.get_queue_attributes(queue_url)
            )

        return self._attributes_cache[queue_url]

    def _get_policy(
        self,
        queue_url: str,
    ) -> dict[str, Any]:
        if queue_url not in self._policy_cache:
            self._policy_cache[queue_url] = (
                self.service.get_queue_policy(queue_url)
            )

        return self._policy_cache[queue_url]

    def _get_tags(
        self,
        queue_url: str,
    ) -> list[dict[str, Any]]:
        if queue_url not in self._tags_cache:
            self._tags_cache[queue_url] = (
                self.service.list_queue_tags(queue_url)
            )

        return self._tags_cache[queue_url]

    def collect_queues(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for queue_url in self._get_queues():
            attributes = self._get_attributes(queue_url)

            queue_arn = attributes.get("QueueArn")

            if not isinstance(queue_arn, str) or not queue_arn:
                continue

            normalized.append(
                {
                    "queue_url": queue_url,
                    "queue_arn": queue_arn,
                    "kms_master_key_id": attributes.get(
                        "KmsMasterKeyId"
                    ),
                    "sqs_managed_sse_enabled": attributes.get(
                        "SqsManagedSseEnabled"
                    ),
                    "policy": self._get_policy(queue_url),
                    "tags": self._get_tags(queue_url),
                }
            )

        return normalized
