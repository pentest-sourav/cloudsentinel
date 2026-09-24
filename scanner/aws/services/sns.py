import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.session import AWS_RETRY_CONFIG


class SNSService:
    """
    Read-only AWS SNS discovery service.

    This service retrieves SNS topic security configuration.
    Security evaluation is handled separately by CloudSentinel rules.
    """

    def __init__(
        self,
        session,
        region_name: str,
    ):
        self.session = session
        self.sns_client = session.client(
            "sns",
            region_name=region_name,
            config=AWS_RETRY_CONFIG,
        )

    def list_topics(self) -> list[dict[str, Any]]:
        """
        Discover all SNS topics in the configured AWS region.

        SNS ListTopics is paginated, so every response page is
        collected until AWS returns no NextToken.
        """
        try:
            topics: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {}

                if next_token:
                    request["NextToken"] = next_token

                response = self.sns_client.list_topics(**request)

                page_topics = response.get("Topics", [])

                if isinstance(page_topics, list):
                    topics.extend(
                        topic
                        for topic in page_topics
                        if isinstance(topic, dict)
                        and isinstance(topic.get("TopicArn"), str)
                        and topic.get("TopicArn")
                    )

                next_token = response.get("NextToken")

                if not isinstance(next_token, str) or not next_token:
                    break

            return topics

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"SNS topic discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while discovering SNS topics: "
                f"{exc}"
            ) from exc

    def get_topic_attributes(
        self,
        topic_arn: str,
    ) -> dict[str, Any]:
        """
        Return SNS topic attributes for security evaluation.
        """
        try:
            response = self.sns_client.get_topic_attributes(
                TopicArn=topic_arn,
            )

            attributes = response.get(
                "Attributes",
                {},
            )

            if not isinstance(attributes, dict):
                return {}

            return attributes

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"SNS topic attributes discovery failed for "
                f"'{topic_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving SNS topic "
                f"attributes for '{topic_arn}': {exc}"
            ) from exc

    def get_topic_policy(
        self,
        topic_arn: str,
    ) -> dict[str, Any]:
        """
        Return and normalize the access policy for an SNS topic.

        SNS returns the Policy attribute as a JSON string.
        The service converts it into a Python dictionary so
        collectors and rules do not need to handle AWS encoding.
        """
        try:
            response = self.sns_client.get_topic_attributes(
                TopicArn=topic_arn,
                AttributeNames=["Policy"],
            )

            attributes = response.get(
                "Attributes",
                {},
            )

            policy = attributes.get(
                "Policy",
                "{}",
            )

            if isinstance(policy, str):
                policy = json.loads(policy)

            if not isinstance(policy, dict):
                return {}

            return policy

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"SNS topic policy discovery failed for "
                f"'{topic_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving SNS topic "
                f"policy for '{topic_arn}': {exc}"
            ) from exc

        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"SNS topic policy response could not be "
                f"parsed for '{topic_arn}': {exc}"
            ) from exc

    def list_tags(
        self,
        topic_arn: str,
    ) -> list[dict[str, Any]]:
        """
        Return tags associated with an SNS topic.
        """
        try:
            response = self.sns_client.list_tags_for_resource(
                ResourceArn=topic_arn,
            )

            tags = response.get(
                "Tags",
                [],
            )

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"SNS topic tag discovery failed for "
                f"'{topic_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving SNS topic "
                f"tags for '{topic_arn}': {exc}"
            ) from exc
