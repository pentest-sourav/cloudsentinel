from typing import Any

from scanner.aws.services.glue import GlueService


class GlueDataCollector:
    """
    Normalize AWS Glue API data for CloudSentinel rules.

    API responses are collected once and cached for the
    lifetime of the collector.
    """

    def __init__(self, service: GlueService):
        self.service = service

        self._jobs_cache: list[dict[str, Any]] | None = None
        self._job_tags_cache: dict[
            str,
            dict[str, str],
        ] = {}
        self._ml_transforms_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_jobs(self) -> list[dict[str, Any]]:
        if self._jobs_cache is None:
            self._jobs_cache = self.service.list_jobs()

        return self._jobs_cache

    def _get_job_tags(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        if resource_arn not in self._job_tags_cache:
            self._job_tags_cache[resource_arn] = (
                self.service.get_tags(resource_arn)
            )

        return self._job_tags_cache[resource_arn]

    def _get_ml_transforms(self) -> list[dict[str, Any]]:
        if self._ml_transforms_cache is None:
            self._ml_transforms_cache = (
                self.service.list_ml_transforms()
            )

        return self._ml_transforms_cache

    @staticmethod
    def _non_system_tags(
        tags: dict[str, str],
    ) -> dict[str, str]:
        return {
            key: value
            for key, value in tags.items()
            if not key.startswith("aws:")
        }

    @staticmethod
    def _job_resource_arn(
        job: dict[str, Any],
    ) -> str | None:
        arn = job.get("JobArn")

        if isinstance(arn, str) and arn:
            return arn

        arn = job.get("Arn")

        if isinstance(arn, str) and arn:
            return arn

        return None

    def collect_jobs(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for job in self._get_jobs():
            name = job.get("Name")

            if not isinstance(name, str) or not name:
                continue

            command = job.get("Command")
            if not isinstance(command, dict):
                command = {}

            glue_version = job.get("GlueVersion")
            if not isinstance(glue_version, str):
                glue_version = None

            command_name = command.get("Name")
            if not isinstance(command_name, str):
                command_name = None

            resource_arn = self._job_resource_arn(job)

            tags: dict[str, str] = {}

            if resource_arn:
                tags = self._non_system_tags(
                    self._get_job_tags(resource_arn)
                )

            normalized.append(
                {
                    "job_name": name,
                    "job_arn": resource_arn,
                    "glue_version": glue_version,
                    "command_name": command_name,
                    "tags": tags,
                    "has_non_system_tags": bool(tags),
                }
            )

        return normalized

    def collect_ml_transforms(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for transform in self._get_ml_transforms():
            transform_id = transform.get("TransformId")

            if (
                not isinstance(transform_id, str)
                or not transform_id
            ):
                continue

            encryption = transform.get(
                "TransformEncryption"
            )

            if not isinstance(encryption, dict):
                encryption = {}

            user_data_encryption = encryption.get(
                "MlUserDataEncryption"
            )

            if not isinstance(user_data_encryption, dict):
                user_data_encryption = {}

            encryption_mode = user_data_encryption.get(
                "MlUserDataEncryptionMode"
            )

            if not isinstance(encryption_mode, str):
                encryption_mode = None

            normalized.append(
                {
                    "transform_id": transform_id,
                    "transform_name": transform.get("Name"),
                    "glue_version": transform.get(
                        "GlueVersion"
                    ),
                    "encryption_mode": encryption_mode,
                    "kms_key_id": user_data_encryption.get(
                        "KmsKeyId"
                    ),
                    "task_run_security_configuration_name": (
                        encryption.get(
                            "TaskRunSecurityConfigurationName"
                        )
                    ),
                }
            )

        return normalized
