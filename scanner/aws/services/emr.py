from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class EMRService:
    """
    Read-only Amazon EMR discovery service.

    AWS collection is isolated from CloudSentinel rule evaluation.
    """

    def __init__(self, session):
        self.session = session
        self.emr_client = create_aws_client(session, "emr")

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
                f"EMR {operation} failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during EMR "
            f"{operation}: {exc}"
        ) from exc

    def list_clusters(self) -> list[dict[str, Any]]:
        try:
            paginator = self.emr_client.get_paginator(
                "list_clusters"
            )

            clusters: list[dict[str, Any]] = []

            for page in paginator.paginate():
                clusters.extend(
                    page.get("Clusters", [])
                )

            return clusters

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "cluster discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_cluster(
        self,
        cluster_id: str,
    ) -> dict[str, Any]:
        if not cluster_id:
            return {}

        try:
            response = self.emr_client.describe_cluster(
                ClusterId=cluster_id,
            )
            return response.get(
                "Cluster",
                {},
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"cluster description for {cluster_id}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_master_instances(
        self,
        cluster_id: str,
    ) -> list[dict[str, Any]]:
        if not cluster_id:
            return []

        try:
            paginator = self.emr_client.get_paginator(
                "list_instances"
            )

            instances: list[dict[str, Any]] = []

            for page in paginator.paginate(
                ClusterId=cluster_id,
                InstanceGroupTypes=["MASTER"],
            ):
                instances.extend(
                    page.get("Instances", [])
                )

            return instances

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"master instance discovery for {cluster_id}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_security_configurations(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.emr_client.get_paginator(
                "list_security_configurations"
            )

            configurations: list[dict[str, Any]] = []

            for page in paginator.paginate():
                configurations.extend(
                    page.get(
                        "SecurityConfigurations",
                        [],
                    )
                )

            return configurations

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "security configuration discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_security_configuration(
        self,
        name: str,
    ) -> dict[str, Any]:
        if not name:
            return {}

        try:
            response = self.emr_client.get_security_configuration(
                Name=name,
            )
            return response

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"security configuration discovery for {name}",
                exc,
            )
            raise AssertionError("unreachable")

    def get_block_public_access_configuration(
        self,
    ) -> dict[str, Any]:
        try:
            response = (
                self.emr_client
                .get_block_public_access_configuration()
            )

            return response.get(
                "BlockPublicAccessConfiguration",
                {},
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "Block Public Access configuration discovery",
                exc,
            )
            raise AssertionError("unreachable")
