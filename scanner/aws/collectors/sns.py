from typing import Any

from scanner.aws.services.sns import SNSService


class SNSDataCollector:
    """
    Normalizes AWS SNS topic configuration data
    for security rules.
    """

    def __init__(self, service: SNSService):
        self.service = service
        self._topics_cache: list[dict[str, Any]] | None = None
        self._attributes_cache: dict[str, dict[str, Any]] = {}
        self._policy_cache: dict[str, dict[str, Any]] = {}
        self._tags_cache: dict[str, list[dict[str, Any]]] = {}

    def _get_topics(self) -> list[dict[str, Any]]:
        """
        Discover SNS topics once and cache the result.
        """
        if self._topics_cache is None:
            self._topics_cache = self.service.list_topics()

        return self._topics_cache

    def collect_topics(self) -> list[dict[str, Any]]:
        """
        Return normalized SNS topic metadata.
        """
        normalized = []

        for topic in self._get_topics():
            topic_arn = topic.get("TopicArn")

            if not topic_arn:
                continue

            normalized.append(
                {
                    "topic_arn": topic_arn,
                }
            )

        return normalized

    def _get_attributes(
        self,
        topic_arn: str,
    ) -> dict[str, Any]:
        """
        Retrieve and cache SNS topic attributes.
        """
        if topic_arn not in self._attributes_cache:
            self._attributes_cache[topic_arn] = (
                self.service.get_topic_attributes(topic_arn)
            )

        return self._attributes_cache[topic_arn]

    def _get_policy(
        self,
        topic_arn: str,
    ) -> dict[str, Any]:
        """
        Retrieve and cache the SNS topic access policy.
        """
        if topic_arn not in self._policy_cache:
            self._policy_cache[topic_arn] = (
                self.service.get_topic_policy(topic_arn)
            )

        return self._policy_cache[topic_arn]

    def _get_tags(
        self,
        topic_arn: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve and cache SNS topic tags.
        """
        if topic_arn not in self._tags_cache:
            self._tags_cache[topic_arn] = (
                self.service.list_tags(topic_arn)
            )

        return self._tags_cache[topic_arn]

    def collect_security(self) -> list[dict[str, Any]]:
        """
        Collect security-relevant configuration for every SNS topic.
        """
        collected = []

        for topic in self._get_topics():
            topic_arn = topic.get("TopicArn")

            if not topic_arn:
                continue

            collected.append(
                {
                    "topic_arn": topic_arn,
                    "attributes": self._get_attributes(topic_arn),
                    "policy": self._get_policy(topic_arn),
                    "tags": self._get_tags(topic_arn),
                }
            )

        return collected
