from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class ECRService:
    """
    Read-only AWS ECR discovery service.

    This service collects repository configuration, registry scanning
    configuration, lifecycle policies, and KMS key metadata.
    Security evaluation is handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.ecr_client = create_aws_client(session, "ecr")
        self.kms_client = create_aws_client(session, "kms")

    def list_repositories(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ecr_client.get_paginator(
                "describe_repositories"
            )

            repositories: list[dict[str, Any]] = []

            for page in paginator.paginate():
                repositories.extend(page.get("repositories", []))

            return repositories

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"ECR repository discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during ECR repository discovery: {exc}"
            ) from exc

    def get_registry_scanning_configuration(self) -> dict[str, Any]:
        try:
            response = self.ecr_client.get_registry_scanning_configuration()

            return response.get(
                "scanningConfiguration",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "ECR registry scanning configuration discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during ECR registry scanning "
                f"configuration discovery: {exc}"
            ) from exc

    def get_lifecycle_policy(
        self,
        repository_name: str,
    ) -> dict[str, Any] | None:
        try:
            response = self.ecr_client.get_lifecycle_policy(
                repositoryName=repository_name,
            )

            return {
                "repository_name": response.get("repositoryName"),
                "registry_id": response.get("registryId"),
                "lifecycle_policy_text": response.get(
                    "lifecyclePolicyText"
                ),
                "last_evaluated_at": response.get("lastEvaluatedAt"),
            }

        except self.ecr_client.exceptions.LifecyclePolicyNotFoundException:
            return None

        except self.ecr_client.exceptions.RepositoryNotFoundException:
            return None

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"ECR lifecycle policy discovery failed for "
                f"{repository_name}: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during ECR lifecycle policy discovery "
                f"for {repository_name}: {exc}"
            ) from exc

    def describe_kms_key(
        self,
        key_id: str,
    ) -> dict[str, Any]:
        try:
            response = self.kms_client.describe_key(
                KeyId=key_id,
            )

            return response.get("KeyMetadata", {})

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"ECR KMS key discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during ECR KMS key discovery: {exc}"
            ) from exc
