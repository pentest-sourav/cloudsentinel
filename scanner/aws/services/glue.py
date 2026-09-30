from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class GlueService:
    """
    Read-only AWS Glue discovery service.

    AWS collection is isolated from CloudSentinel rule evaluation.
    """

    def __init__(self, session):
        self.session = session
        self.glue_client = create_aws_client(session, "glue")

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
                f"Glue {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Glue "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Glue "
            f"{operation}: {exc}"
        ) from exc

    def list_jobs(self) -> list[dict[str, Any]]:
        try:
            paginator = self.glue_client.get_paginator(
                "get_jobs"
            )

            jobs: list[dict[str, Any]] = []

            for page in paginator.paginate():
                jobs.extend(page.get("Jobs", []))

            return jobs

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "job discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_tags(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        if not resource_arn:
            return {}

        try:
            response = self.glue_client.get_tags(
                ResourceArn=resource_arn,
            )

            tags = response.get("Tags", {})

            if not isinstance(tags, dict):
                return {}

            return {
                str(key): str(value)
                for key, value in tags.items()
            }

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_ml_transforms(self) -> list[dict[str, Any]]:
        try:
            transforms: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                kwargs: dict[str, Any] = {
                    "MaxResults": 1000,
                }

                if next_token:
                    kwargs["NextToken"] = next_token

                response = self.glue_client.get_ml_transforms(
                    **kwargs
                )

                page_transforms = response.get(
                    "Transforms",
                    [],
                )

                if isinstance(page_transforms, list):
                    transforms.extend(
                        transform
                        for transform in page_transforms
                        if isinstance(transform, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                    or token == next_token
                ):
                    break

                next_token = token

            return transforms

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "ML transform discovery",
                exc,
            )
            raise AssertionError("unreachable")
