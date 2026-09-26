from typing import Any

from scanner.aws.services.redshift import RedshiftService


class RedshiftDataCollector:
    """
    Normalize Redshift API responses for CloudSentinel rules.

    The collector performs AWS data collection and normalization only.
    Security decisions remain inside the rule layer.
    """

    def __init__(self, service: RedshiftService):
        self.service = service
        self._clusters_cache: list[dict[str, Any]] | None = None
        self._parameters_cache: dict[str, list[dict[str, Any]]] = {}
        self._logging_cache: dict[str, dict[str, Any]] = {}
        self._security_groups_cache: list[dict[str, Any]] | None = None

    def _get_clusters(self) -> list[dict[str, Any]]:
        if self._clusters_cache is None:
            self._clusters_cache = self.service.describe_clusters()

        return self._clusters_cache

    def _get_cluster_parameters(
        self,
        parameter_group_name: str | None,
    ) -> list[dict[str, Any]]:
        if not parameter_group_name:
            return []

        if parameter_group_name not in self._parameters_cache:
            self._parameters_cache[parameter_group_name] = (
                self.service.describe_cluster_parameters(
                    parameter_group_name
                )
            )

        return self._parameters_cache[parameter_group_name]

    def _get_logging_status(
        self,
        cluster_identifier: str,
    ) -> dict[str, Any]:
        if cluster_identifier not in self._logging_cache:
            self._logging_cache[cluster_identifier] = (
                self.service.describe_logging_status(
                    cluster_identifier
                )
            )

        return self._logging_cache[cluster_identifier]

    def _get_security_groups(
        self,
        group_ids: list[str],
    ) -> dict[str, dict[str, Any]]:
        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_security_groups(group_ids)
            )

        return {
            group.get("GroupId"): group
            for group in self._security_groups_cache
            if group.get("GroupId")
        }

    @staticmethod
    def _parameter_value(
        parameters: list[dict[str, Any]],
        parameter_name: str,
    ) -> str | None:
        for parameter in parameters:
            if (
                parameter.get("ParameterName", "").lower()
                == parameter_name.lower()
            ):
                return parameter.get("ParameterValue")

        return None

    @staticmethod
    def _security_group_ingress(
        security_groups: dict[str, dict[str, Any]],
        group_ids: list[str],
        cluster_port: int | None,
    ) -> list[dict[str, Any]]:
        if cluster_port is None:
            return []

        ingress: list[dict[str, Any]] = []

        for group_id in group_ids:
            group = security_groups.get(group_id)
            if not group:
                continue

            for permission in group.get("IpPermissions", []) or []:
                protocol = permission.get("IpProtocol")

                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                # Redshift.15 is concerned with the cluster port.
                # A protocol of -1 permits all traffic, so it is
                # relevant even when explicit port fields are absent.
                covers_cluster_port = protocol == "-1"

                if (
                    from_port is not None
                    and to_port is not None
                    and from_port <= cluster_port <= to_port
                ):
                    covers_cluster_port = True

                if not covers_cluster_port:
                    continue

                ingress.append(
                    {
                        "security_group_id": group_id,
                        "ip_protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "ipv4_ranges": [
                            item.get("CidrIp")
                            for item in permission.get(
                                "IpRanges", []
                            )
                            if item.get("CidrIp")
                        ],
                        "ipv6_ranges": [
                            item.get("CidrIpv6")
                            for item in permission.get(
                                "Ipv6Ranges", []
                            )
                            if item.get("CidrIpv6")
                        ],
                    }
                )

        return ingress

    def collect_clusters(self) -> list[dict[str, Any]]:
        """
        Return normalized Redshift cluster data.

        Missing optional fields remain None instead of being interpreted
        as insecure values, preventing false positives caused by
        incomplete AWS responses.
        """
        clusters = self._get_clusters()

        if not clusters:
            return []

        parameter_group_names = {
            parameter_group.get("ParameterGroupName")
            for cluster in clusters
            for parameter_group in (
                cluster.get("ClusterParameterGroups") or []
            )
            if parameter_group.get("ParameterGroupName")
        }

        for parameter_group_name in parameter_group_names:
            self._get_cluster_parameters(parameter_group_name)

        security_group_ids = [
            group.get("VpcSecurityGroupId")
            for cluster in clusters
            for group in (cluster.get("VpcSecurityGroups") or [])
            if group.get("VpcSecurityGroupId")
        ]

        security_groups = self._get_security_groups(
            security_group_ids
        )

        normalized: list[dict[str, Any]] = []

        for cluster in clusters:
            cluster_id = cluster.get("ClusterIdentifier")

            if not cluster_id:
                continue

            parameter_groups = cluster.get(
                "ClusterParameterGroups"
            ) or []

            primary_parameter_group = None
            for parameter_group in parameter_groups:
                name = parameter_group.get("ParameterGroupName")
                if name:
                    primary_parameter_group = name
                    break

            parameters = self._get_cluster_parameters(
                primary_parameter_group
            )

            logging_status = self._get_logging_status(cluster_id)

            vpc_security_group_ids = [
                group.get("VpcSecurityGroupId")
                for group in (
                    cluster.get("VpcSecurityGroups") or []
                )
                if group.get("VpcSecurityGroupId")
            ]

            normalized.append(
                {
                    "cluster_identifier": cluster_id,
                    "publicly_accessible": cluster.get(
                        "PubliclyAccessible"
                    ),
                    "encrypted": cluster.get("Encrypted"),
                    "automated_snapshot_retention_period": cluster.get(
                        "AutomatedSnapshotRetentionPeriod"
                    ),
                    "allow_version_upgrade": cluster.get(
                        "AllowVersionUpgrade"
                    ),
                    "enhanced_vpc_routing": cluster.get(
                        "EnhancedVpcRouting"
                    ),
                    "master_username": cluster.get(
                        "MasterUsername"
                    ),
                    "multi_az": cluster.get("MultiAZ"),
                    "cluster_port": (
                        cluster.get("Endpoint") or {}
                    ).get("Port"),
                    "require_ssl": self._parameter_value(
                        parameters,
                        "require_ssl",
                    ),
                    "parameter_group_name": primary_parameter_group,
                    "audit_logging_enabled": logging_status.get(
                        "LoggingEnabled"
                    ),
                    "vpc_security_group_ids": vpc_security_group_ids,
                    "security_group_ingress": (
                        self._security_group_ingress(
                            security_groups,
                            vpc_security_group_ids,
                            (
                                cluster.get("Endpoint") or {}
                            ).get("Port"),
                        )
                    ),
                }
            )

        return normalized
