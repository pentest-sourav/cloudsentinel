from typing import Any

from scanner.aws.services.kms import KMSService


class KMSDataCollector:
    """
    Normalize AWS KMS data for CloudSentinel security rules.

    Missing optional API data is preserved as None so that rules
    can distinguish unknown state from an actual insecure state.
    """

    def __init__(self, service: KMSService):
        self.service = service
        self._keys_cache: list[dict[str, Any]] | None = None
        self._metadata_cache: dict[str, dict[str, Any]] = {}
        self._rotation_cache: dict[str, bool | None] = {}
        self._policy_cache: dict[str, dict[str, Any] | None] = {}

    def _get_keys(self) -> list[dict[str, Any]]:
        if self._keys_cache is None:
            self._keys_cache = self.service.list_keys()

        return self._keys_cache

    def _get_metadata(self, key_id: str) -> dict[str, Any]:
        if key_id not in self._metadata_cache:
            self._metadata_cache[key_id] = self.service.describe_key(
                key_id
            )

        return self._metadata_cache[key_id]

    def _get_rotation_status(self, key_id: str) -> bool | None:
        if key_id not in self._rotation_cache:
            self._rotation_cache[key_id] = (
                self.service.get_key_rotation_status(key_id)
            )

        return self._rotation_cache[key_id]

    def _get_policy(self, key_id: str) -> dict[str, Any] | None:
        if key_id not in self._policy_cache:
            self._policy_cache[key_id] = self.service.get_key_policy(
                key_id
            )

        return self._policy_cache[key_id]

    def collect_keys(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for key in self._get_keys():
            key_id = key.get("KeyId")

            if not key_id:
                continue

            metadata = self._get_metadata(key_id)

            key_manager = metadata.get("KeyManager")
            key_state = metadata.get("KeyState")

            normalized.append(
                {
                    "key_id": key_id,
                    "key_arn": metadata.get("Arn"),
                    "description": metadata.get("Description"),
                    "key_manager": key_manager,
                    "key_state": key_state,
                    "key_usage": metadata.get("KeyUsage"),
                    "key_spec": metadata.get("KeySpec"),
                    "origin": metadata.get("Origin"),
                    "multi_region": metadata.get("MultiRegion"),
                    "deletion_date": metadata.get("DeletionDate"),
                    "valid_to": metadata.get("ValidTo"),
                    "rotation_enabled": (
                        self._get_rotation_status(key_id)
                        if key_manager == "CUSTOMER"
                        else None
                    ),
                    "key_policy": self._get_policy(key_id),
                }
            )

        return normalized
