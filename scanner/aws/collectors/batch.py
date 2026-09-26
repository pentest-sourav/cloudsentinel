from __future__ import annotations

from typing import Any

from scanner.aws.services.batch import BatchService


class BatchDataCollector:
    """Normalize AWS Batch resources for CloudSentinel."""

    def __init__(self, service: BatchService):
        self.service = service

        self._job_queues_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._scheduling_policies_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._scheduling_policy_details_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._compute_environments_cache: (
            list[dict[str, Any]] | None
        ) = None

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> tuple[dict[str, str], bool]:
        if not isinstance(tags, dict):
            return {}, False

        normalized: dict[str, str] = {}

        for key, value in tags.items():
            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            normalized[key] = str(value)

        return normalized, True

    def _tag_resource(
        self,
        resource_arn: Any,
    ) -> tuple[dict[str, str], bool]:
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return {}, False

        raw_tags = self.service.list_tags_for_resource(
            resource_arn
        )

        return self._normalize_tags(raw_tags)

    def _get_job_queues(self) -> list[dict[str, Any]]:
        if self._job_queues_cache is None:
            self._job_queues_cache = (
                self.service.describe_job_queues()
            )

        return self._job_queues_cache

    def _get_scheduling_policies(
        self,
    ) -> list[dict[str, Any]]:
        if self._scheduling_policies_cache is None:
            self._scheduling_policies_cache = (
                self.service.list_scheduling_policies()
            )

        return self._scheduling_policies_cache

    def _get_scheduling_policy_details(
        self,
    ) -> list[dict[str, Any]]:
        if self._scheduling_policy_details_cache is None:
            arns = [
                item.get("arn")
                for item in self._get_scheduling_policies()
                if isinstance(item.get("arn"), str)
            ]

            details: list[dict[str, Any]] = []

            for start in range(0, len(arns), 100):
                details.extend(
                    self.service.describe_scheduling_policies(
                        arns[start:start + 100]
                    )
                )

            self._scheduling_policy_details_cache = details

        return self._scheduling_policy_details_cache

    def _get_compute_environments(
        self,
    ) -> list[dict[str, Any]]:
        if self._compute_environments_cache is None:
            self._compute_environments_cache = (
                self.service.describe_compute_environments()
            )

        return self._compute_environments_cache

    @staticmethod
    def _tag_result(
        *,
        resource_name: str,
        resource_arn: str,
        resource_type: str,
        tags: dict[str, str],
        tag_data_available: bool,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = {
            "resource_name": resource_name,
            "resource_arn": resource_arn,
            "resource_type": resource_type,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

        if extra:
            result.update(extra)

        return result

    def collect_job_queues(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for queue in self._get_job_queues():
            arn = queue.get("jobQueueArn")
            name = queue.get("jobQueueName")

            if (
                not isinstance(arn, str)
                or not arn
                or not isinstance(name, str)
                or not name
            ):
                continue

            tags, available = self._tag_resource(arn)

            normalized.append(
                self._tag_result(
                    resource_name=name,
                    resource_arn=arn,
                    resource_type="batch_job_queue",
                    tags=tags,
                    tag_data_available=available,
                    extra={
                        "job_queue_state": queue.get(
                            "state"
                        ),
                        "job_queue_status": queue.get(
                            "status"
                        ),
                    },
                )
            )

        return normalized

    def collect_scheduling_policies(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for policy in self._get_scheduling_policy_details():
            arn = policy.get("arn")
            name = policy.get("name")

            if (
                not isinstance(arn, str)
                or not arn
                or not isinstance(name, str)
                or not name
            ):
                continue

            tags, available = self._tag_resource(arn)

            normalized.append(
                self._tag_result(
                    resource_name=name,
                    resource_arn=arn,
                    resource_type=(
                        "batch_scheduling_policy"
                    ),
                    tags=tags,
                    tag_data_available=available,
                )
            )

        return normalized

    def collect_compute_environments(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for environment in self._get_compute_environments():
            arn = environment.get(
                "computeEnvironmentArn"
            )
            name = environment.get(
                "computeEnvironmentName"
            )

            if (
                not isinstance(arn, str)
                or not arn
                or not isinstance(name, str)
                or not name
            ):
                continue

            tags, available = self._tag_resource(arn)

            normalized.append(
                self._tag_result(
                    resource_name=name,
                    resource_arn=arn,
                    resource_type=(
                        "batch_compute_environment"
                    ),
                    tags=tags,
                    tag_data_available=available,
                    extra={
                        "compute_environment_type": (
                            environment.get("type")
                        ),
                        "compute_resources": (
                            environment.get(
                                "computeResources"
                            )
                        ),
                    },
                )
            )

        return normalized

    def collect_managed_compute_resource_tags(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for environment in self._get_compute_environments():
            environment_type = environment.get("type")

            compute_resources = environment.get(
                "computeResources"
            )

            if (
                environment_type != "MANAGED"
                or not isinstance(
                    compute_resources,
                    dict,
                )
            ):
                continue

            compute_type = compute_resources.get(
                "type"
            )

            if compute_type in {
                "FARGATE",
                "FARGATE_SPOT",
            }:
                continue

            arn = environment.get(
                "computeEnvironmentArn"
            )

            name = environment.get(
                "computeEnvironmentName"
            )

            tags = compute_resources.get("tags")

            if (
                not isinstance(arn, str)
                or not arn
                or not isinstance(name, str)
                or not name
            ):
                continue

            normalized_tags, available = (
                self._normalize_tags(tags)
            )

            normalized.append(
                self._tag_result(
                    resource_name=name,
                    resource_arn=arn,
                    resource_type=(
                        "batch_compute_environment_resources"
                    ),
                    tags=normalized_tags,
                    tag_data_available=available,
                    extra={
                        "compute_environment_type": (
                            environment_type
                        ),
                        "compute_resource_type": (
                            compute_type
                        ),
                    },
                )
            )

        return normalized
