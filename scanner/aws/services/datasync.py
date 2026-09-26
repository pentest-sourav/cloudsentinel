from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class DataSyncService:
    """Read-only AWS DataSync discovery service."""

    def __init__(self, session):
        self.session = session
        self.datasync_client = create_aws_client(
            session,
            "datasync",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS DataSync {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AWS DataSync "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AWS DataSync "
            f"{operation}: {exc}"
        ) from exc

    def list_tasks(self) -> list[dict[str, Any]]:
        try:
            paginator = self.datasync_client.get_paginator(
                "list_tasks"
            )

            tasks: list[dict[str, Any]] = []

            for page in paginator.paginate():
                items = page.get("Tasks", [])

                if isinstance(items, list):
                    tasks.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return tasks

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "list_tasks",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_task(
        self,
        task_arn: str,
    ) -> dict[str, Any]:
        if not isinstance(task_arn, str) or not task_arn:
            return {}

        try:
            response = self.datasync_client.describe_task(
                TaskArn=task_arn,
            )

            return (
                response
                if isinstance(response, dict)
                else {}
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"describe_task for {task_arn}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return {}

        try:
            paginator = self.datasync_client.get_paginator(
                "list_tags_for_resource"
            )

            tags: dict[str, str] = {}

            for page in paginator.paginate(
                ResourceArn=resource_arn,
            ):
                tag_list = page.get("Tags", [])

                if not isinstance(tag_list, list):
                    continue

                for tag in tag_list:
                    if not isinstance(tag, dict):
                        continue

                    key = tag.get("Key")

                    if not isinstance(key, str) or not key:
                        continue

                    tags[key] = str(
                        tag.get("Value", "")
                    )

            return tags

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")
