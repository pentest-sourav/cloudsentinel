from typing import Any

from scanner.aws.services.ec2 import EC2Service


class EC2TaggingDataCollector:
    """
    Normalizes native EC2 Describe* responses for AWS Security Hub
    resource-tagging controls.

    The existing EC2Service is intentionally reused so the scanner
    shares the same AWS client, retry configuration, and test seams.
    """

    def __init__(self, service: EC2Service):
        self.service = service

    @staticmethod
    def _normalize(
        resources: list[dict[str, Any]],
        id_key: str,
        resource_type: str,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        if not isinstance(resources, list):
            return normalized

        for resource in resources:
            if not isinstance(resource, dict):
                continue

            resource_id = resource.get(id_key)

            if not resource_id:
                continue

            tags = resource.get("Tags", [])

            if not isinstance(tags, (list, dict)):
                tags = []

            normalized.append(
                {
                    "resource_id": str(resource_id),
                    "resource_type": resource_type,
                    "tags": tags,
                }
            )

        return normalized

    def collect_instances(self) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_instances(),
            "InstanceId",
            "ec2_instance",
        )

    def collect_network_interfaces(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_network_interfaces(),
            "NetworkInterfaceId",
            "network_interface",
        )

    def collect_security_groups(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_all_security_groups(),
            "GroupId",
            "security_group",
        )

    def collect_volumes(self) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_all_volumes(),
            "VolumeId",
            "ebs_volume",
        )

    def collect_elastic_ips(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_addresses(),
            "AllocationId",
            "elastic_ip",
        )

    def collect_vpcs(self) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_vpcs(),
            "VpcId",
            "vpc",
        )

    def collect_subnets(self) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_subnets(),
            "SubnetId",
            "subnet",
        )

    def collect_internet_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_internet_gateways(),
            "InternetGatewayId",
            "internet_gateway",
        )

    def collect_nat_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_nat_gateways(),
            "NatGatewayId",
            "nat_gateway",
        )

    def collect_network_acls(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_network_acls(),
            "NetworkAclId",
            "network_acl",
        )

    def collect_route_tables(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_route_tables(),
            "RouteTableId",
            "route_table",
        )

    def collect_flow_logs(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_flow_logs(),
            "FlowLogId",
            "vpc_flow_log",
        )

    def collect_vpc_peering_connections(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_vpc_peering_connections(),
            "VpcPeeringConnectionId",
            "vpc_peering_connection",
        )

    def collect_vpn_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_vpn_gateways(),
            "VpnGatewayId",
            "vpn_gateway",
        )

    def collect_transit_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._normalize(
            self.service.describe_transit_gateways(),
            "TransitGatewayId",
            "transit_gateway",
        )
