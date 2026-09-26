from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AthenaService:
    """Read-only AWS Athena discovery service."""

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
        self.athena_client = create_aws_client(session, "athena")

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
                f"Athena {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Athena "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Athena "
            f"{operation}: {exc}"
        ) from exc

    def list_data_catalogs(self) -> list[dict[str, Any]]:
        try:
            paginator = self.athena_client.get_paginator(
                "list_data_catalogs"
            )

            catalogs: list[dict[str, Any]] = []

            for page in paginator.paginate():
                catalogs.extend(
                    page.get("DataCatalogsSummary", [])
                )

            return catalogs

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "data catalog discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_workgroups(self) -> list[dict[str, Any]]:
        try:
            paginator = self.athena_client.get_paginator(
                "list_work_groups"
            )

            workgroups: list[dict[str, Any]] = []

            for page in paginator.paginate():
                workgroups.extend(
                    page.get("WorkGroups", [])
                )

            return workgroups

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "workgroup discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_workgroup(
        self,
        name: str,
    ) -> dict[str, Any]:
        if not name:
            return {}

        try:
            response = self.athena_client.get_work_group(
                WorkGroup=name,
            )

            workgroup = response.get(
                "WorkGroup",
                {},
            )

            if not isinstance(workgroup, dict):
                return {}

            return workgroup

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"workgroup detail discovery for {name}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> list[dict[str, str]]:
        if not resource_arn:
            return []

        try:
            paginator = self.athena_client.get_paginator(
                "list_tags_for_resource"
            )

            tags: list[dict[str, str]] = []

            for page in paginator.paginate(
                ResourceARN=resource_arn,
            ):
                page_tags = page.get("Tags", [])

                if isinstance(page_tags, list):
                    tags.extend(
                        tag
                        for tag in page_tags
                        if isinstance(tag, dict)
                    )

            return tags

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")

    def build_resource_arn(
        self,
        resource_type: str,
        resource_name: str,
    ) -> str | None:
        if (
            not self.account_id
            or not self.region_name
            or not resource_name
        ):
            return None

        partition = "aws"

        get_partition = getattr(
            self.session,
            "get_partition_for_region",
            None,
        )

        if callable(get_partition):
            try:
                resolved = get_partition(
                    self.region_name
                )

                if (
                    isinstance(resolved, str)
                    and resolved
                ):
                    partition = resolved

            except Exception:
                pass

        return (
            f"arn:{partition}:athena:"
            f"{self.region_name}:"
            f"{self.account_id}:"
            f"{resource_type}/{resource_name}"
        )
