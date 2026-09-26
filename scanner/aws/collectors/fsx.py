from typing import Any

from scanner.aws.services.fsx import FSxService


class FSxDataCollector:
    """
    Normalize Amazon FSx configuration for security rules.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(
        self,
        service: FSxService,
    ):
        self.service = service

        self._file_systems_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_file_systems(self) -> list[dict[str, Any]]:
        if self._file_systems_cache is None:
            self._file_systems_cache = (
                self.service.list_file_systems()
            )

        return self._file_systems_cache

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def collect_file_systems(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for file_system in self._get_file_systems():
            resource_id = file_system.get("FileSystemId")

            if (
                not isinstance(resource_id, str)
                or not resource_id
            ):
                continue

            file_system_type = file_system.get(
                "FileSystemType"
            )

            if not isinstance(file_system_type, str):
                file_system_type = ""

            openzfs = self._as_dict(
                file_system.get("OpenZFSConfiguration")
            )
            lustre = self._as_dict(
                file_system.get("LustreConfiguration")
            )
            ontap = self._as_dict(
                file_system.get("OntapConfiguration")
            )
            windows = self._as_dict(
                file_system.get("WindowsConfiguration")
            )

            normalized.append(
                {
                    "resource_id": resource_id,
                    "resource_type": "fsx_file_system",
                    "resource_arn": file_system.get(
                        "ResourceARN"
                    ),
                    "file_system_type": file_system_type,
                    "openzfs_copy_tags_to_backups": (
                        openzfs.get("CopyTagsToBackups")
                        is True
                    ),
                    "openzfs_copy_tags_to_volumes": (
                        openzfs.get("CopyTagsToVolumes")
                        is True
                    ),
                    "openzfs_deployment_type": (
                        openzfs.get("DeploymentType")
                    ),
                    "lustre_copy_tags_to_backups": (
                        lustre.get("CopyTagsToBackups")
                        is True
                    ),
                    "ontap_deployment_type": (
                        ontap.get("DeploymentType")
                    ),
                    "windows_deployment_type": (
                        windows.get("DeploymentType")
                    ),
                }
            )

        return normalized
