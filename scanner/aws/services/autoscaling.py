from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AutoScalingService:
    """Read-only AWS EC2 Auto Scaling discovery service."""

    def __init__(
        self,
        session,
        account_id: str | None = None,
        region_name: str | None = None,
    ):
        self.session = session
        self.account_id = account_id
        self.region_name = region_name or getattr(
            session,
            "region_name",
            None,
        )
        self.autoscaling_client = create_aws_client(
            session,
            "autoscaling",
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
                f"Auto Scaling {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Auto Scaling "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Auto Scaling "
            f"{operation}: {exc}"
        ) from exc

    def list_auto_scaling_groups(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.autoscaling_client.get_paginator(
                "describe_auto_scaling_groups"
            )

            groups: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_groups = page.get(
                    "AutoScalingGroups",
                    [],
                )

                if isinstance(page_groups, list):
                    groups.extend(
                        item
                        for item in page_groups
                        if isinstance(item, dict)
                    )

            return groups

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "Auto Scaling group discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_launch_configurations(
        self,
        names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.autoscaling_client.get_paginator(
                "describe_launch_configurations"
            )

            configurations: list[dict[str, Any]] = []

            if not names:
                pages = paginator.paginate()
                for page in pages:
                    page_items = page.get(
                        "LaunchConfigurations",
                        [],
                    )
                    if isinstance(page_items, list):
                        configurations.extend(
                            item
                            for item in page_items
                            if isinstance(item, dict)
                        )
                return configurations

            # AWS limits LaunchConfigurationNames to 50 per request.
            for start in range(0, len(names), 50):
                batch = names[start : start + 50]

                for page in paginator.paginate(
                    LaunchConfigurationNames=batch
                ):
                    page_items = page.get(
                        "LaunchConfigurations",
                        [],
                    )

                    if isinstance(page_items, list):
                        configurations.extend(
                            item
                            for item in page_items
                            if isinstance(item, dict)
                        )

            return configurations

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "launch configuration discovery",
                exc,
            )
            raise AssertionError("unreachable")
