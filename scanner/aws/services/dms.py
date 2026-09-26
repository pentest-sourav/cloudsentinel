from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class DMSService:
    """Read-only AWS DMS discovery service."""

    def __init__(self, session):
        self.session = session
        self.dms_client = create_aws_client(
            session,
            "dms",
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
                f"AWS DMS {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AWS DMS "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AWS DMS "
            f"{operation}: {exc}"
        ) from exc

    def _paginate(
        self,
        operation: str,
        result_key: str,
        **kwargs,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.dms_client.get_paginator(
                operation
            )

            results: list[dict[str, Any]] = []

            for page in paginator.paginate(**kwargs):
                items = page.get(result_key, [])

                if isinstance(items, list):
                    results.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return results

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                operation,
                exc,
            )
            raise AssertionError("unreachable")

    def describe_replication_instances(
        self,
    ) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_replication_instances",
            "ReplicationInstances",
        )

    def describe_certificates(
        self,
    ) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_certificates",
            "Certificates",
        )

    def describe_event_subscriptions(
        self,
    ) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_event_subscriptions",
            "EventSubscriptions",
        )

    def describe_replication_subnet_groups(
        self,
    ) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_replication_subnet_groups",
            "ReplicationSubnetGroups",
        )

    def describe_replication_tasks(
        self,
    ) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_replication_tasks",
            "ReplicationTasks",
        )

    def describe_endpoints(
        self,
    ) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_endpoints",
            "Endpoints",
        )

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
            response = (
                self.dms_client
                .list_tags_for_resource(
                    ResourceArn=resource_arn,
                )
            )

            tag_list = response.get(
                "TagList",
                [],
            )

            if not isinstance(tag_list, list):
                return {}

            tags: dict[str, str] = {}

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
