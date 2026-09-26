from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AppSyncService:
    """
    Read-only AWS AppSync discovery service.

    Discovers GraphQL APIs and returns the configuration required
    by CloudSentinel AppSync security posture rules.
    """

    def __init__(self, session):
        self.appsync_client = create_aws_client(
            session,
            "appsync",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS AppSync {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AppSync "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AppSync "
            f"{operation}: {exc}"
        ) from exc

    def list_graphql_apis(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.appsync_client.get_paginator(
                "list_graphql_apis"
            )

            apis: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    "graphqlApis",
                    [],
                )

                if isinstance(entries, list):
                    apis.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return apis

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "GraphQL API discovery",
                exc,
            )
            raise AssertionError("unreachable")
