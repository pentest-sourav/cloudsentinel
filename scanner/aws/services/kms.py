from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class KMSService:
    """
    Read-only AWS KMS discovery service.

    This service collects KMS key configuration, key policies,
    and key grants. Security evaluation is handled separately
    by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.kms_client = create_aws_client(session, "kms")

    def list_keys(self) -> list[dict[str, Any]]:
        try:
            paginator = self.kms_client.get_paginator("list_keys")

            keys: list[dict[str, Any]] = []

            for page in paginator.paginate():
                keys.extend(page.get("Keys", []))

            return keys

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"KMS key discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during KMS key discovery: {exc}"
            ) from exc

    def describe_key(self, key_id: str) -> dict[str, Any]:
        try:
            response = self.kms_client.describe_key(KeyId=key_id)
            return response.get("KeyMetadata", {})

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"KMS key description failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during KMS key description: {exc}"
            ) from exc

    def get_key_rotation_status(self, key_id: str) -> bool | None:
        try:
            response = self.kms_client.get_key_rotation_status(
                KeyId=key_id
            )

            return response.get("KeyRotationEnabled")

        except self.kms_client.exceptions.KMSInvalidStateException:
            return None

        except self.kms_client.exceptions.NotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"KMS key rotation status discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during KMS key rotation discovery: "
                f"{exc}"
            ) from exc

    def get_key_policy(
        self,
        key_id: str,
        policy_name: str = "default",
    ) -> dict[str, Any] | None:
        try:
            response = self.kms_client.get_key_policy(
                KeyId=key_id,
                PolicyName=policy_name,
            )

            policy = response.get("Policy")

            if not policy:
                return None

            return {
                "policy": policy,
                "policy_name": policy_name,
            }

        except self.kms_client.exceptions.NotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"KMS key policy discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during KMS key policy discovery: "
                f"{exc}"
            ) from exc

    def list_grants(self, key_id: str) -> list[dict[str, Any]]:
        try:
            paginator = self.kms_client.get_paginator("list_grants")

            grants: list[dict[str, Any]] = []

            for page in paginator.paginate(KeyId=key_id):
                grants.extend(page.get("Grants", []))

            return grants

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"KMS grant discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during KMS grant discovery: {exc}"
            ) from exc
