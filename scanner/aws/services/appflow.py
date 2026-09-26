from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AppFlowService:
    """
    Read-only Amazon AppFlow discovery service.

    AWS API collection is isolated from CloudSentinel rule evaluation.
    """

    def __init__(self, session):
        self.session = session
        self.appflow_client = create_aws_client(
            session,
            "appflow",
        )

    def _raise_api_error(
        self,
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
                f"AppFlow {operation} failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during AppFlow "
            f"{operation}: {exc}"
        ) from exc

    def list_flows(self) -> list[dict[str, Any]]:
        """
        Discover all AppFlow flows in the current account/region.
        """
        try:
            paginator = self.appflow_client.get_paginator(
                "list_flows"
            )

            flows: list[dict[str, Any]] = []

            for page in paginator.paginate():
                items = page.get("flows", [])

                if isinstance(items, list):
                    flows.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return flows

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "flow discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        """
        Retrieve tags attached to an AppFlow flow.
        """
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return {}

        try:
            response = (
                self.appflow_client.list_tags_for_resource(
                    resourceArn=resource_arn,
                )
            )

            tags = response.get("tags", {})

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
