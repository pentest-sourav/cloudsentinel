from typing import Any

from scanner.aws.services.secretsmanager import (
    SecretsManagerService,
)


class SecretsManagerDataCollector:
    """
    Normalize AWS Secrets Manager metadata for CloudSentinel rules.

    Secret values are never retrieved.
    """

    def __init__(
        self,
        service: SecretsManagerService,
    ):
        self.service = service

        self._secrets_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._descriptions_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def _get_secrets(
        self,
    ) -> list[dict[str, Any]]:
        if self._secrets_cache is None:
            self._secrets_cache = (
                self.service.list_secrets()
            )

        return self._secrets_cache

    def _get_description(
        self,
        secret_id: str,
    ) -> dict[str, Any]:
        if secret_id not in self._descriptions_cache:
            self._descriptions_cache[secret_id] = (
                self.service.describe_secret(
                    secret_id
                )
            )

        return self._descriptions_cache[
            secret_id
        ]

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> list[dict[str, str]]:
        if not isinstance(tags, list):
            return []

        normalized: list[dict[str, str]] = []

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")
            value = tag.get("Value", "")

            if not isinstance(key, str) or not key:
                continue

            normalized.append(
                {
                    "Key": key,
                    "Value": (
                        value
                        if isinstance(value, str)
                        else str(value)
                    ),
                }
            )

        return normalized

    def collect_secrets(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for entry in self._get_secrets():
            secret_id = entry.get("ARN") or entry.get(
                "Name"
            )

            if not isinstance(secret_id, str) or not secret_id:
                continue

            details = self._get_description(
                secret_id
            )

            if not details:
                continue

            resource_arn = details.get(
                "ARN"
            ) or entry.get("ARN")

            resource_name = details.get(
                "Name"
            ) or entry.get("Name")

            if not isinstance(
                resource_arn,
                str,
            ) or not resource_arn:
                continue

            normalized.append(
                {
                    "resource_id": resource_name
                    if isinstance(
                        resource_name,
                        str,
                    )
                    else resource_arn,
                    "resource_arn": resource_arn,
                    "name": resource_name,
                    "rotation_enabled": details.get(
                        "RotationEnabled"
                    ),
                    "rotation_rules": details.get(
                        "RotationRules"
                    )
                    or {},
                    "last_rotated_date": details.get(
                        "LastRotatedDate"
                    ),
                    "last_accessed_date": details.get(
                        "LastAccessedDate"
                    ),
                    "next_rotation_date": details.get(
                        "NextRotationDate"
                    ),
                    "last_changed_date": details.get(
                        "LastChangedDate"
                    ),
                    "tags": self._normalize_tags(
                        details.get("Tags")
                    ),
                    "owning_service": details.get(
                        "OwningService"
                    ),
                    "resource": details,
                }
            )

        return normalized
