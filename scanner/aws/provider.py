import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.common.providers.base import (
    CloudProvider,
    ProviderIdentity,
)


class AWSProvider(CloudProvider):
    provider_name = "aws"

    def __init__(self, session: boto3.Session):
        self.session = session
        self.sts_client = session.client("sts")

    def verify_identity(self) -> ProviderIdentity:
        try:
            response = self.sts_client.get_caller_identity()

            account_id = response["Account"]
            arn = response.get("Arn")

            return ProviderIdentity(
                provider=self.provider_name,
                account_id=account_id,
                display_name=arn,
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"AWS identity verification failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during identity verification: {exc}"
            ) from exc
