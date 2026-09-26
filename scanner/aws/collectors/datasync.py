from __future__ import annotations

from typing import Any


class DataSyncDataCollector:
    """Normalizes AWS DataSync task data for rule execution."""

    def __init__(self, service):
        self.service = service
        self._tasks: list[dict[str, Any]] | None = None
        self._task_details: dict[str, dict[str, Any]] = {}
        self._task_tags: dict[str, dict[str, str]] = {}

    @staticmethod
    def _non_system_tags(
        tags: dict[str, str],
    ) -> dict[str, str]:
        if not isinstance(tags, dict):
            return {}

        return {
            key: value
            for key, value in tags.items()
            if not key.lower().startswith("aws:")
        }

    def _discover_tasks(self) -> list[dict[str, Any]]:
        if self._tasks is None:
            self._tasks = self.service.list_tasks()

        return self._tasks

    def _get_task_detail(
        self,
        task_arn: str,
    ) -> dict[str, Any]:
        if task_arn not in self._task_details:
            self._task_details[task_arn] = (
                self.service.describe_task(task_arn)
            )

        return self._task_details[task_arn]

    def _get_tags(
        self,
        task_arn: str,
    ) -> dict[str, str]:
        if task_arn not in self._task_tags:
            raw_tags = (
                self.service.list_tags_for_resource(
                    task_arn
                )
            )

            self._task_tags[task_arn] = (
                self._non_system_tags(raw_tags)
            )

        return self._task_tags[task_arn]

    def collect_tasks(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []

        for task in self._discover_tasks():
            task_arn = task.get("TaskArn")
            task_name = task.get("Name")

            if not isinstance(task_arn, str) or not task_arn:
                continue

            detail = self._get_task_detail(task_arn)
            tags = self._get_tags(task_arn)

            options = detail.get("Options", {})
            if not isinstance(options, dict):
                options = {}

            task_mode = detail.get(
                "TaskMode",
                task.get("TaskMode"),
            )

            log_level = options.get("LogLevel")

            cloudwatch_log_group_arn = detail.get(
                "CloudWatchLogGroupArn"
            )

            result.append(
                {
                    "resource_name": (
                        task_name
                        or detail.get("Name")
                        or task_arn
                    ),
                    "resource_arn": task_arn,
                    "resource_type": "AWS::DataSync::Task",
                    "task_mode": task_mode,
                    "status": detail.get(
                        "Status",
                        task.get("Status"),
                    ),
                    "log_level": log_level,
                    "cloudwatch_log_group_arn": (
                        cloudwatch_log_group_arn
                    ),
                    "tags": tags,
                    "tag_data_available": True,
                    "has_non_system_tags": bool(tags),
                }
            )

        return result
