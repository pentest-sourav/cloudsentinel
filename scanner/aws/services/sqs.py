import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class SQSService:
    """
    Read-only AWS SQS discovery service.

    This service retrieves queue attributes, access policies, and tags.
    Security evaluation is handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.sqs_client = create_aws_client(session, "sqs")

    def list_queues(self) -> list[str]:
        try:
            queue_urls: list[str] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {}

                if next_token:
                    request["NextToken"] = next_token

                response = self.sqs_client.list_queues(**request)

                urls = response.get("QueueUrls", [])

                if isinstance(urls, list):
                    queue_urls.extend(
                        url
                        for url in urls
                        if isinstance(url, str) and url
                    )

                next_token = response.get("NextToken")

                if not isinstance(next_token, str) or not next_token:
                    break

            return queue_urls

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"SQS queue discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during SQS queue discovery: {exc}"
            ) from exc

    def get_queue_attributes(
        self,
        queue_url: str,
    ) -> dict[str, Any]:
        try:
            response = self.sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=[
                    "QueueArn",
                    "Policy",
                    "KmsMasterKeyId",
                    "SqsManagedSseEnabled",
                ],
            )

            attributes = response.get("Attributes", {})

            if not isinstance(attributes, dict):
                return {}

            return attributes

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"SQS queue attributes discovery failed for "
                f"'{queue_url}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving SQS queue "
                f"attributes for '{queue_url}': {exc}"
            ) from exc

    def get_queue_policy(
        self,
        queue_url: str,
    ) -> dict[str, Any]:
        try:
            response = self.sqs_client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["Policy"],
            )

            attributes = response.get("Attributes", {})
            policy = attributes.get("Policy", "{}")

            if isinstance(policy, str):
                policy = json.loads(policy)

            if not isinstance(policy, dict):
                return {}

            return policy

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"SQS queue policy discovery failed for "
                f"'{queue_url}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving SQS queue policy "
                f"for '{queue_url}': {exc}"
            ) from exc

        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"SQS queue policy response could not be parsed for "
                f"'{queue_url}': {exc}"
            ) from exc

    def list_queue_tags(
        self,
        queue_url: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.sqs_client.list_queue_tags(
                QueueUrl=queue_url,
            )

            tags = response.get("Tags", {})

            if isinstance(tags, dict):
                return [
                    {"Key": key, "Value": value}
                    for key, value in tags.items()
                    if isinstance(key, str)
                ]

            if isinstance(tags, list):
                return [
                    tag
                    for tag in tags
                    if isinstance(tag, dict)
                ]

            return []

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"SQS queue tag discovery failed for "
                f"'{queue_url}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving SQS queue tags "
                f"for '{queue_url}': {exc}"
            ) from exc
