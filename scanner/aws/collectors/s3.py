from typing import Any

from scanner.aws.services.s3 import S3Service


class S3DataCollector:
    def __init__(self, service: S3Service):
        self.service = service
        self.buckets: list[dict[str, Any]] | None = None

    def _get_buckets(self) -> list[dict[str, Any]]:
        if self.buckets is None:
            self.buckets = self.service.list_buckets()

        return self.buckets

    def collect_buckets(self) -> list[dict[str, Any]]:
        return self._get_buckets()

    def collect_public_access(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "public_access_block": (
                        self.service.get_public_access_block(
                            bucket_name
                        )
                    ),
                }
            )

        return collected

    def collect_encryption(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "encryption_configuration": (
                        self.service.get_bucket_encryption(
                            bucket_name
                        )
                    ),
                }
            )

        return collected

    def collect_bucket_policy(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "policy_status": (
                        self.service.get_bucket_policy_status(
                            bucket_name
                        )
                    ),
                }
            )

        return collected

    def collect_tls_policy(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "policy": self.service.get_bucket_policy(
                        bucket_name
                    ),
                }
            )

        return collected

    def collect_acl(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "acl": self.service.get_bucket_acl(
                        bucket_name
                    ),
                }
            )

        return collected

    def collect_versioning(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "versioning_status": (
                        self.service.get_bucket_versioning(
                            bucket_name
                        )
                    ),
                }
            )

        return collected

    def collect_logging(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "logging_configuration": (
                        self.service.get_bucket_logging(
                            bucket_name
                        )
                    ),
                }
            )

        return collected

    def collect_object_lock(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "object_lock_configuration": (
                        self.service.get_object_lock_configuration(
                            bucket_name
                        )
                    ),
                }
            )

        return collected

    def collect_ownership(self) -> list[dict[str, Any]]:
        buckets = self._get_buckets()

        collected = []

        for bucket in buckets:
            bucket_name = bucket["name"]

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "ownership_configuration": (
                        self.service.get_bucket_ownership_controls(
                            bucket_name
                        )
                    ),
                }
            )

        return collected
