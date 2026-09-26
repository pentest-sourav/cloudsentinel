from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AmplifyService:
    """
    Read-only AWS Amplify discovery service.

    The service layer is responsible only for AWS API access.
    Security evaluation is handled by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.amplify_client = create_aws_client(
            session,
            "amplify",
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
                f"Amplify {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Amplify "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Amplify "
            f"{operation}: {exc}"
        ) from exc

    def list_apps(self) -> list[dict[str, Any]]:
        """
        Discover all Amplify apps visible to the current
        credentials in the current region.
        """
        try:
            paginator = self.amplify_client.get_paginator(
                "list_apps"
            )

            apps: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_apps = page.get("apps", [])

                if isinstance(page_apps, list):
                    apps.extend(
                        app
                        for app in page_apps
                        if isinstance(app, dict)
                    )

            return apps

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "app discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_branches(
        self,
        app_id: str,
    ) -> list[dict[str, Any]]:
        """
        Discover all branches belonging to an Amplify app.
        """
        if not isinstance(app_id, str) or not app_id:
            return []

        try:
            paginator = self.amplify_client.get_paginator(
                "list_branches"
            )

            branches: list[dict[str, Any]] = []

            for page in paginator.paginate(
                appId=app_id,
            ):
                page_branches = page.get(
                    "branches",
                    [],
                )

                if isinstance(page_branches, list):
                    branches.extend(
                        branch
                        for branch in page_branches
                        if isinstance(branch, dict)
                    )

            return branches

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"branch discovery for app {app_id}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        """
        Return tags for an Amplify app or branch ARN.
        """
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return {}

        try:
            response = self.amplify_client.list_tags_for_resource(
                resourceArn=resource_arn,
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
