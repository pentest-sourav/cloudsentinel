from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class Route53Service:
    """
    Read-only Amazon Route 53 discovery service.

    This service retrieves health checks, hosted zones,
    resource tags, and DNS query logging configuration.
    No mutating Route 53 operation is performed.
    """

    def __init__(self, session):
        self.session = session
        self.route53_client = create_aws_client(
            session,
            "route53",
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
                f"Route 53 {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Route 53 "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Route 53 "
            f"{operation}: {exc}"
        ) from exc

    def list_health_checks(self) -> list[dict[str, Any]]:
        try:
            health_checks: list[dict[str, Any]] = []
            marker: str | None = None

            while True:
                request: dict[str, Any] = {
                    "MaxItems": "1000",
                }

                if marker:
                    request["Marker"] = marker

                response = self.route53_client.list_health_checks(
                    **request
                )

                entries = response.get(
                    "HealthChecks",
                    [],
                )

                if isinstance(entries, list):
                    health_checks.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                if not response.get("IsTruncated"):
                    break

                next_marker = response.get("NextMarker")

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return health_checks

        except Exception as exc:
            self._raise_api_error(
                "health-check discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_hosted_zones(self) -> list[dict[str, Any]]:
        try:
            hosted_zones: list[dict[str, Any]] = []
            marker: str | None = None

            while True:
                request: dict[str, Any] = {
                    "MaxItems": "100",
                }

                if marker:
                    request["Marker"] = marker

                response = self.route53_client.list_hosted_zones(
                    **request
                )

                entries = response.get(
                    "HostedZones",
                    [],
                )

                if isinstance(entries, list):
                    hosted_zones.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                if not response.get("IsTruncated"):
                    break

                next_marker = response.get("NextMarker")

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return hosted_zones

        except Exception as exc:
            self._raise_api_error(
                "hosted-zone discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_type: str,
        resource_id: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.route53_client.list_tags_for_resource(
                ResourceType=resource_type,
                ResourceId=resource_id,
            )

            resource_tag_set = response.get(
                "ResourceTagSet",
                {},
            )

            if not isinstance(resource_tag_set, dict):
                return []

            tags = resource_tag_set.get(
                "Tags",
                [],
            )

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except Exception as exc:
            self._raise_api_error(
                f"{resource_type} tag discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_query_logging_configs(
        self,
    ) -> list[dict[str, Any]]:
        try:
            configurations: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {
                    "MaxResults": "100",
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.route53_client.list_query_logging_configs(
                        **request
                    )
                )

                entries = response.get(
                    "QueryLoggingConfigs",
                    [],
                )

                if isinstance(entries, list):
                    configurations.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return configurations

        except Exception as exc:
            self._raise_api_error(
                "query-logging discovery",
                exc,
            )
            raise AssertionError("unreachable")
