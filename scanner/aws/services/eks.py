from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class EKSService:
    """
    Read-only Amazon EKS discovery service.
    """

    def __init__(self, session):
        self.session = session
        self.client = create_aws_client(session, "eks")

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
                f"EKS {operation} failed: {code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during EKS {operation}: {exc}"
        ) from exc

    def list_clusters(self) -> list[str]:
        try:
            paginator = self.client.get_paginator(
                "list_clusters"
            )

            clusters: list[str] = []

            for page in paginator.paginate():
                clusters.extend(
                    page.get("clusters", [])
                )

            return clusters

        except Exception as exc:
            self._raise_api_error(
                "cluster discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_cluster(
        self,
        cluster_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.client.describe_cluster(
                name=cluster_name,
            )

            return response.get("cluster") or {}

        except Exception as exc:
            self._raise_api_error(
                f"cluster lookup for {cluster_name}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_nodegroups(
        self,
        cluster_name: str,
    ) -> list[str]:
        try:
            paginator = self.client.get_paginator(
                "list_nodegroups"
            )

            nodegroups: list[str] = []

            for page in paginator.paginate(
                clusterName=cluster_name,
            ):
                nodegroups.extend(
                    page.get("nodegroups", [])
                )

            return nodegroups

        except Exception as exc:
            self._raise_api_error(
                f"node group discovery for {cluster_name}",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_nodegroup(
        self,
        cluster_name: str,
        nodegroup_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.client.describe_nodegroup(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name,
            )

            return response.get("nodegroup") or {}

        except Exception as exc:
            self._raise_api_error(
                f"node group lookup for {nodegroup_name}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_identity_provider_configs(
        self,
        cluster_name: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.client.get_paginator(
                "list_identity_provider_configs"
            )

            configs: list[dict[str, Any]] = []

            for page in paginator.paginate(
                clusterName=cluster_name,
            ):
                configs.extend(
                    page.get(
                        "identityProviderConfigs",
                        [],
                    )
                )

            return configs

        except Exception as exc:
            self._raise_api_error(
                "identity provider discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_identity_provider_config(
        self,
        cluster_name: str,
        provider_type: str,
        provider_name: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.client.describe_identity_provider_config(
                    clusterName=cluster_name,
                    identityProviderConfig={
                        "type": provider_type,
                        "name": provider_name,
                    },
                )
            )

            return (
                response.get(
                    "identityProviderConfig"
                )
                or {}
            )

        except Exception as exc:
            self._raise_api_error(
                "identity provider lookup",
                exc,
            )
            raise AssertionError("unreachable")
