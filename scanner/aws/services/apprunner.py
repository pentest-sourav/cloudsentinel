from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AppRunnerService:
    """
    Read-only AWS App Runner discovery service.

    The service layer is responsible only for AWS API access.
    Security evaluation is handled by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.apprunner_client = create_aws_client(
            session,
            "apprunner",
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
                f"App Runner {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during App Runner "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during App Runner "
            f"{operation}: {exc}"
        ) from exc

    def list_services(self) -> list[dict[str, Any]]:
        """
        Discover all App Runner services visible to the
        current credentials in the current region.
        """
        try:
            paginator = self.apprunner_client.get_paginator(
                "list_services"
            )

            services: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_services = page.get(
                    "ServiceSummaryList",
                    [],
                )

                if isinstance(page_services, list):
                    services.extend(
                        service
                        for service in page_services
                        if isinstance(service, dict)
                    )

            return services

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "service discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_vpc_connectors(self) -> list[dict[str, Any]]:
        """
        Discover all App Runner VPC connectors visible to
        the current credentials in the current region.
        """
        try:
            paginator = self.apprunner_client.get_paginator(
                "list_vpc_connectors"
            )

            connectors: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_connectors = page.get(
                    "VpcConnectors",
                    [],
                )

                if isinstance(page_connectors, list):
                    connectors.extend(
                        connector
                        for connector in page_connectors
                        if isinstance(connector, dict)
                    )

            return connectors

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "VPC connector discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> list[dict[str, str]]:
        """
        Return tags for an App Runner resource ARN.

        App Runner returns Tags as a list of:
            {"Key": "...", "Value": "..."}
        """
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return []

        try:
            response = (
                self.apprunner_client.list_tags_for_resource(
                    ResourceArn=resource_arn,
                )
            )

            tags = response.get("Tags", [])

            if not isinstance(tags, list):
                return []

            normalized: list[dict[str, str]] = []

            for tag in tags:
                if not isinstance(tag, dict):
                    continue

                key = tag.get("Key")
                value = tag.get("Value", "")

                if not isinstance(key, str):
                    continue

                normalized.append(
                    {
                        "Key": key,
                        "Value": str(value),
                    }
                )

            return normalized

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")
