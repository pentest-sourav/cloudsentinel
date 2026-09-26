from typing import Any

from scanner.aws.services.efs import EFSService


class EFSDataCollector:
    """
    Normalize Amazon EFS configuration for security rules.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(
        self,
        service: EFSService,
    ):
        self.service = service

        self._file_systems_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._access_points_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_file_systems(self) -> list[dict[str, Any]]:
        if self._file_systems_cache is None:
            self._file_systems_cache = (
                self.service.list_file_systems()
            )

        return self._file_systems_cache

    def _get_access_points(self) -> list[dict[str, Any]]:
        if self._access_points_cache is None:
            self._access_points_cache = (
                self.service.list_access_points()
            )

        return self._access_points_cache

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

    def collect_file_systems(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for file_system in self._get_file_systems():
            file_system_id = file_system.get(
                "FileSystemId"
            )

            if (
                not isinstance(file_system_id, str)
                or not file_system_id
            ):
                continue

            backup_policy = file_system.get(
                "BackupPolicy",
                {},
            )

            if not isinstance(backup_policy, dict):
                backup_policy = {}

            normalized.append(
                {
                    "resource_id": file_system_id,
                    "resource_type": "efs_file_system",
                    "resource_arn": file_system.get(
                        "FileSystemArn"
                    ),
                    "name": file_system.get("Name"),
                    "encrypted": (
                        file_system.get("Encrypted")
                        is True
                    ),
                    "kms_key_id": file_system.get(
                        "KmsKeyId"
                    ),
                    "backup": (
                        file_system.get("Backup")
                        is True
                    ),
                    "backup_policy_status": (
                        backup_policy.get("Status")
                    ),
                    "life_cycle_state": file_system.get(
                        "LifeCycleState"
                    ),
                    "performance_mode": file_system.get(
                        "PerformanceMode"
                    ),
                    "throughput_mode": file_system.get(
                        "ThroughputMode"
                    ),
                    "tags": self._normalize_tags(
                        file_system.get("Tags")
                    ),
                }
            )

        return normalized

    def collect_access_points(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for access_point in self._get_access_points():
            access_point_id = access_point.get(
                "AccessPointId"
            )

            if (
                not isinstance(access_point_id, str)
                or not access_point_id
            ):
                continue

            root_directory = access_point.get(
                "RootDirectory",
                {},
            )

            if not isinstance(root_directory, dict):
                root_directory = {}

            path = root_directory.get("Path")

            posix_user = access_point.get(
                "PosixUser"
            )

            if not isinstance(posix_user, dict):
                posix_user = {}

            normalized.append(
                {
                    "resource_id": access_point_id,
                    "resource_type": "efs_access_point",
                    "resource_arn": access_point.get(
                        "AccessPointArn"
                    ),
                    "file_system_id": access_point.get(
                        "FileSystemId"
                    ),
                    "root_directory_path": path,
                    "root_directory_creation_info": (
                        root_directory.get(
                            "CreationInfo"
                        )
                    ),
                    "posix_uid": posix_user.get("Uid"),
                    "posix_gid": posix_user.get("Gid"),
                    "secondary_gids": posix_user.get(
                        "SecondaryGids"
                    ),
                }
            )

        return normalized
