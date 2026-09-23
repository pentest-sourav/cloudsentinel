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
