from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class ELBService:
    """
    Read-only Elastic Load Balancing discovery service.

    Supports Application, Network, and Gateway Load Balancers
    through the ELBv2 API.
    """

    def __init__(self, session):
        self.elbv2_client = create_aws_client(
            session,
            "elbv2",
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
                f"AWS ELB {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during ELB "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during ELB "
            f"{operation}: {exc}"
        ) from exc

    def list_load_balancers(
        self,
    ) -> list[dict[str, Any]]:
        load_balancers: list[dict[str, Any]] = []
        marker: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "PageSize": 400,
                }

                if marker:
                    request["Marker"] = marker

                response = (
                    self.elbv2_client
                    .describe_load_balancers(
                        **request,
                    )
                )

                entries = response.get(
                    "LoadBalancers",
                    [],
                )

                if isinstance(entries, list):
                    load_balancers.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                next_marker = response.get(
                    "NextMarker"
                )

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return load_balancers

        except Exception as exc:
            self._raise_api_error(
                "load-balancer discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_listeners(
        self,
        load_balancer_arn: str,
    ) -> list[dict[str, Any]]:
        listeners: list[dict[str, Any]] = []
        marker: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "LoadBalancerArn": load_balancer_arn,
                    "PageSize": 400,
                }

                if marker:
                    request["Marker"] = marker

                response = (
                    self.elbv2_client
                    .describe_listeners(
                        **request,
                    )
                )

                entries = response.get(
                    "Listeners",
                    [],
                )

                if isinstance(entries, list):
                    listeners.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                next_marker = response.get(
                    "NextMarker"
                )

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return listeners

        except Exception as exc:
            self._raise_api_error(
                "listener discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_target_groups(
        self,
        load_balancer_arn: str,
    ) -> list[dict[str, Any]]:
        target_groups: list[dict[str, Any]] = []
        marker: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "LoadBalancerArn": load_balancer_arn,
                    "PageSize": 400,
                }

                if marker:
                    request["Marker"] = marker

                response = (
                    self.elbv2_client
                    .describe_target_groups(
                        **request,
                    )
                )

                entries = response.get(
                    "TargetGroups",
                    [],
                )

                if isinstance(entries, list):
                    target_groups.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                next_marker = response.get(
                    "NextMarker"
                )

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return target_groups

        except Exception as exc:
            self._raise_api_error(
                "target-group discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_load_balancer_attributes(
        self,
        load_balancer_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = (
                self.elbv2_client
                .describe_load_balancer_attributes(
                    LoadBalancerArn=load_balancer_arn,
                )
            )

            attributes = response.get(
                "Attributes",
                [],
            )

            if not isinstance(attributes, list):
                return []

            return [
                attribute
                for attribute in attributes
                if isinstance(attribute, dict)
            ]

        except Exception as exc:
            self._raise_api_error(
                "load-balancer attribute discovery",
                exc,
            )
            raise AssertionError("unreachable")
