from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class CloudFormationService:
    """
    Read-only AWS CloudFormation discovery service.

    The service layer is responsible only for AWS API access.
    Security evaluation is handled by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.cloudformation_client = create_aws_client(
            session,
            "cloudformation",
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
                f"CloudFormation {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during CloudFormation "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during CloudFormation "
            f"{operation}: {exc}"
        ) from exc

    def describe_stacks(self) -> list[dict[str, Any]]:
        """
        Discover CloudFormation stacks visible to the current
        credentials in the current region.

        Pagination is handled through the AWS SDK paginator.
        """
        try:
            paginator = self.cloudformation_client.get_paginator(
                "describe_stacks"
            )

            stacks: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_stacks = page.get("Stacks", [])

                if isinstance(page_stacks, list):
                    stacks.extend(
                        stack
                        for stack in page_stacks
                        if isinstance(stack, dict)
                    )

            return stacks

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "stack discovery",
                exc,
            )
            raise AssertionError("unreachable")
