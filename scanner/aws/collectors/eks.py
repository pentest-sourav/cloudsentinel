from typing import Any

from scanner.aws.services.eks import EKSService


class EKSDataCollector:
    """
    Normalize Amazon EKS resources for CloudSentinel rules.
    """

    def __init__(self, service: EKSService):
        self.service = service

        self._clusters: list[dict[str, Any]] | None = None
        self._nodegroups: list[dict[str, Any]] | None = None
        self._identity_provider_configs: (
            list[dict[str, Any]] | None
        ) = None

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def collect_clusters(self) -> list[dict[str, Any]]:
        if self._clusters is not None:
            return self._clusters

        self._clusters = []

        cluster_names = self.service.list_clusters()

        for cluster_name in cluster_names:
            cluster = self.service.describe_cluster(
                cluster_name
            )

            name = cluster.get("name")
            arn = cluster.get("arn")

            if not isinstance(name, str) or not name:
                continue

            if not isinstance(arn, str) or not arn:
                continue

            resources_vpc_config = self._dict(
                cluster.get("resourcesVpcConfig")
            )

            logging = self._dict(
                cluster.get("logging")
            )

            self._clusters.append(
                {
                    "resource_id": name,
                    "resource_arn": arn,
                    "cluster_name": name,
                    "version": cluster.get("version"),
                    "endpoint_public_access": (
                        resources_vpc_config.get(
                            "endpointPublicAccess"
                        )
                    ),
                    "endpoint_private_access": (
                        resources_vpc_config.get(
                            "endpointPrivateAccess"
                        )
                    ),
                    "public_access_cidrs": self._list(
                        resources_vpc_config.get(
                            "publicAccessCidrs"
                        )
                    ),
                    "logging": logging,
                    "cluster_logging": self._list(
                        logging.get("clusterLogging")
                    ),
                    "tags": self._dict(
                        cluster.get("tags")
                    ),
                    "resource": cluster,
                }
            )

        return self._clusters

    def collect_nodegroups(
        self,
    ) -> list[dict[str, Any]]:
        if self._nodegroups is not None:
            return self._nodegroups

        self._nodegroups = []

        for cluster in self.collect_clusters():
            cluster_name = cluster["cluster_name"]

            nodegroup_names = (
                self.service.list_nodegroups(
                    cluster_name
                )
            )

            for nodegroup_name in nodegroup_names:
                nodegroup = (
                    self.service.describe_nodegroup(
                        cluster_name,
                        nodegroup_name,
                    )
                )

                arn = nodegroup.get(
                    "nodegroupArn"
                )

                if not isinstance(arn, str) or not arn:
                    continue

                name = nodegroup.get(
                    "nodegroupName"
                ) or nodegroup_name

                self._nodegroups.append(
                    {
                        "resource_id": name,
                        "resource_arn": arn,
                        "cluster_name": (
                            nodegroup.get(
                                "clusterName"
                            )
                            or cluster_name
                        ),
                        "nodegroup_name": name,
                        "version": nodegroup.get(
                            "version"
                        ),
                        "status": nodegroup.get(
                            "status"
                        ),
                        "tags": self._dict(
                            nodegroup.get("tags")
                        ),
                        "resource": nodegroup,
                    }
                )

        return self._nodegroups

    def collect_identity_provider_configs(
        self,
    ) -> list[dict[str, Any]]:
        if self._identity_provider_configs is not None:
            return self._identity_provider_configs

        self._identity_provider_configs = []

        for cluster in self.collect_clusters():
            cluster_name = cluster["cluster_name"]

            configs = (
                self.service.list_identity_provider_configs(
                    cluster_name
                )
            )

            for config in configs:
                provider_type = config.get("type")
                provider_name = config.get("name")

                if not isinstance(
                    provider_type,
                    str,
                ) or not provider_type:
                    continue

                if not isinstance(
                    provider_name,
                    str,
                ) or not provider_name:
                    continue

                detail = (
                    self.service
                    .describe_identity_provider_config(
                        cluster_name=cluster_name,
                        provider_type=provider_type,
                        provider_name=provider_name,
                    )
                )

                oidc = self._dict(
                    detail.get("oidc")
                )

                arn = oidc.get(
                    "identityProviderConfigArn"
                )

                if not isinstance(
                    arn,
                    str,
                ) or not arn:
                    continue

                self._identity_provider_configs.append(
                    {
                        "resource_id": provider_name,
                        "resource_arn": arn,
                        "cluster_name": (
                            oidc.get(
                                "clusterName"
                            )
                            or cluster_name
                        ),
                        "provider_type": provider_type,
                        "provider_name": provider_name,
                        "status": oidc.get(
                            "status"
                        ),
                        "tags": self._dict(
                            oidc.get("tags")
                        ),
                        "resource": detail,
                    }
                )

        return self._identity_provider_configs

    def collect(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "eks_clusters": self.collect_clusters(),
            "eks_nodegroups": self.collect_nodegroups(),
            "eks_identity_provider_configs": (
                self.collect_identity_provider_configs()
            ),
        }
