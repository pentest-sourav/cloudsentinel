from typing import Any

from scanner.aws.services.ecr import ECRService


class ECRDataCollector:
    """
    Normalize AWS ECR data for CloudSentinel security rules.

    Optional API data is preserved as None so rules can distinguish
    an unknown state from an actual insecure configuration.
    """

    def __init__(self, service: ECRService):
        self.service = service

        self._repositories_cache: list[dict[str, Any]] | None = None
        self._registry_scanning_cache: dict[str, Any] | None = None
        self._lifecycle_cache: dict[
            str,
            dict[str, Any] | None,
        ] = {}
        self._kms_cache: dict[
            str,
            dict[str, Any] | None,
        ] = {}

    def _get_repositories(self) -> list[dict[str, Any]]:
        if self._repositories_cache is None:
            self._repositories_cache = self.service.list_repositories()

        return self._repositories_cache

    def _get_registry_scanning_configuration(
        self,
    ) -> dict[str, Any]:
        if self._registry_scanning_cache is None:
            self._registry_scanning_cache = (
                self.service.get_registry_scanning_configuration()
            )

        return self._registry_scanning_cache

    def _get_lifecycle_policy(
        self,
        repository_name: str,
    ) -> dict[str, Any] | None:
        if repository_name not in self._lifecycle_cache:
            self._lifecycle_cache[repository_name] = (
                self.service.get_lifecycle_policy(repository_name)
            )

        return self._lifecycle_cache[repository_name]

    def _get_kms_metadata(
        self,
        key_id: str,
    ) -> dict[str, Any] | None:
        if key_id not in self._kms_cache:
            self._kms_cache[key_id] = self.service.describe_kms_key(
                key_id
            )

        return self._kms_cache[key_id]

    def collect_repositories(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        registry_scanning = self._get_registry_scanning_configuration()

        scan_type = registry_scanning.get("scanType")
        scan_rules = registry_scanning.get("rules") or []

        for repository in self._get_repositories():
            repository_name = repository.get("repositoryName")

            if not repository_name:
                continue

            scanning_configuration = (
                repository.get("imageScanningConfiguration") or {}
            )

            encryption_configuration = (
                repository.get("encryptionConfiguration") or {}
            )

            kms_key = encryption_configuration.get("kmsKey")
            kms_metadata = (
                self._get_kms_metadata(kms_key)
                if kms_key
                else None
            )

            lifecycle_policy = self._get_lifecycle_policy(
                repository_name
            )

            normalized.append(
                {
                    "repository_name": repository_name,
                    "repository_arn": repository.get("repositoryArn"),
                    "repository_uri": repository.get("repositoryUri"),
                    "registry_id": repository.get("registryId"),
                    "image_tag_mutability": repository.get(
                        "imageTagMutability"
                    ),
                    "image_tag_mutability_exclusion_filters": (
                        repository.get(
                            "imageTagMutabilityExclusionFilters"
                        )
                        or []
                    ),
                    "scan_on_push": scanning_configuration.get(
                        "scanOnPush"
                    ),
                    "encryption_type": encryption_configuration.get(
                        "encryptionType"
                    ),
                    "kms_key": kms_key,
                    "kms_key_manager": (
                        kms_metadata.get("KeyManager")
                        if kms_metadata
                        else None
                    ),
                    "registry_scan_type": scan_type,
                    "registry_scan_rules": scan_rules,
                    "lifecycle_policy": lifecycle_policy,
                }
            )

        return normalized
