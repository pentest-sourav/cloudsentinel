from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class BatchService:
    """Read-only AWS Batch discovery service."""

    def __init__(self, session):
        self.session = session
        self.batch_client = create_aws_client(
            session,
            "batch",
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
                f"AWS Batch {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AWS Batch "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AWS Batch "
            f"{operation}: {exc}"
        ) from exc

    def describe_job_queues(self) -> list[dict[str, Any]]:
        try:
            job_queues: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {
                    "maxResults": 100,
                }

                if next_token:
                    request["nextToken"] = next_token

                response = self.batch_client.describe_job_queues(
                    **request
                )

                items = response.get(
                    "jobQueues",
                    [],
                )

                if isinstance(items, list):
                    job_queues.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

                token = response.get("nextToken")

                if (
                    not isinstance(token, str)
                    or not token
                    or token == next_token
                ):
                    break

                next_token = token

            return job_queues

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "describe_job_queues",
                exc,
            )
            raise AssertionError("unreachable")

    def list_scheduling_policies(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.batch_client.get_paginator(
                "list_scheduling_policies"
            )

            policies: list[dict[str, Any]] = []

            for page in paginator.paginate():
                items = page.get(
                    "schedulingPolicies",
                    [],
                )

                if isinstance(items, list):
                    policies.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return policies

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "list_scheduling_policies",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_scheduling_policies(
        self,
        arns: list[str],
    ) -> list[dict[str, Any]]:
        if not isinstance(arns, list) or not arns:
            return []

        normalized_arns = [
            arn
            for arn in arns
            if isinstance(arn, str) and arn
        ]

        if not normalized_arns:
            return []

        try:
            response = (
                self.batch_client
                .describe_scheduling_policies(
                    arns=normalized_arns[:100],
                )
            )

            items = response.get(
                "schedulingPolicies",
                [],
            )

            return [
                item
                for item in items
                if isinstance(item, dict)
            ]

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "describe_scheduling_policies",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_compute_environments(
        self,
    ) -> list[dict[str, Any]]:
        try:
            compute_environments: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {
                    "maxResults": 100,
                }

                if next_token:
                    request["nextToken"] = next_token

                response = (
                    self.batch_client
                    .describe_compute_environments(
                        **request
                    )
                )

                items = response.get(
                    "computeEnvironments",
                    [],
                )

                if isinstance(items, list):
                    compute_environments.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

                token = response.get("nextToken")

                if (
                    not isinstance(token, str)
                    or not token
                    or token == next_token
                ):
                    break

                next_token = token

            return compute_environments

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "describe_compute_environments",
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
            response = (
                self.batch_client
                .list_tags_for_resource(
                    resourceArn=resource_arn,
                )
            )

            tags = response.get(
                "tags",
                {},
            )

            if not isinstance(tags, dict):
                return {}

            return {
                str(key): str(value)
                for key, value in tags.items()
                if isinstance(key, str)
            }

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")
