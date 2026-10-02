from typing import Any

from scanner.aws.services.vpc import VPCService


class VPCDataCollector:
    """
    Normalizes AWS VPC, Internet Gateway, default Security Group,
    VPC Flow Log, and Network ACL configuration data for security rules.
    """

    def __init__(self, service: VPCService):
        self.service = service
        self._vpcs_cache: list[dict[str, Any]] | None = None
        self._internet_gateways_cache: list[dict[str, Any]] | None = None
        self._default_security_groups_cache: (
            list[dict[str, Any]] | None
        ) = None
        self._flow_logs_cache: list[dict[str, Any]] | None = None
        self._network_acls_cache: list[dict[str, Any]] | None = None
        self._vpc_endpoints_cache: list[dict[str, Any]] | None = None
        self._vpc_bpa_options_cache: dict[str, Any] | None = None
        self._subnets_cache: list[dict[str, Any]] | None = None
        self._client_vpn_endpoints_cache: list[dict[str, Any]] | None = None
        self._vpn_connections_cache: list[dict[str, Any]] | None = None
        self._spot_fleet_requests_cache: list[dict[str, Any]] | None = None
        self._network_interfaces_cache: list[dict[str, Any]] | None = None

    def _get_vpcs(self) -> list[dict[str, Any]]:
        if self._vpcs_cache is None:
            self._vpcs_cache = self.service.describe_vpcs()

        return self._vpcs_cache

    def _get_internet_gateways(self) -> list[dict[str, Any]]:
        if self._internet_gateways_cache is None:
            self._internet_gateways_cache = (
                self.service.describe_internet_gateways()
            )

        return self._internet_gateways_cache

    def _get_default_security_groups(self) -> list[dict[str, Any]]:
        if self._default_security_groups_cache is None:
            self._default_security_groups_cache = (
                self.service.describe_default_security_groups()
            )

        return self._default_security_groups_cache

    def _get_flow_logs(self) -> list[dict[str, Any]]:
        if self._flow_logs_cache is None:
            self._flow_logs_cache = self.service.describe_flow_logs()

        return self._flow_logs_cache

    def _get_vpc_endpoints(self) -> list[dict[str, Any]]:
        if self._vpc_endpoints_cache is None:
            self._vpc_endpoints_cache = (
                self.service.describe_vpc_endpoints()
            )

        return self._vpc_endpoints_cache

    def _get_vpc_block_public_access_options(
        self,
    ) -> dict[str, Any]:
        if self._vpc_bpa_options_cache is None:
            self._vpc_bpa_options_cache = (
                self.service
                .describe_vpc_block_public_access_options()
            )

        return self._vpc_bpa_options_cache

    def collect_vpc_block_public_access_options(
        self,
    ) -> dict[str, Any]:
        """
        Normalize the regional VPC Block Public Access configuration.

        EC2.172 evaluates account/Region-level BPA configuration,
        so this data source intentionally returns one normalized
        record rather than one record per VPC.
        """
        options = self._get_vpc_block_public_access_options()

        region = options.get(
            "AwsRegion"
        )

        if not region:
            region = getattr(
                self.service.ec2_client.meta,
                "region_name",
                None,
            )

        return {
            "region": region,
            "internet_gateway_block_mode": options.get(
                "InternetGatewayBlockMode"
            ),
            "state": options.get("State"),
            "managed_by": options.get("ManagedBy"),
            "exclusions_allowed": options.get(
                "ExclusionsAllowed"
            ),
        }

    def _get_subnets(self) -> list[dict[str, Any]]:
        if self._subnets_cache is None:
            self._subnets_cache = self.service.describe_subnets()

        return self._subnets_cache

    def collect_subnet_public_ip_coverage(
        self,
    ) -> list[dict[str, Any]]:
        normalized = []

        for subnet in self._get_subnets():
            subnet_id = subnet.get("SubnetId")

            if not subnet_id:
                continue

            normalized.append(
                {
                    "subnet_id": subnet_id,
                    "vpc_id": subnet.get("VpcId"),
                    "map_public_ip_on_launch": bool(
                        subnet.get(
                            "MapPublicIpOnLaunch",
                            False,
                        )
                    ),
                }
            )

        return normalized

    def collect_unused_network_acl_coverage(
        self,
    ) -> list[dict[str, Any]]:
        normalized = []

        for network_acl in self._get_network_acls():
            network_acl_id = network_acl.get("NetworkAclId")

            if not network_acl_id:
                continue

            normalized.append(
                {
                    "network_acl_id": network_acl_id,
                    "vpc_id": network_acl.get("VpcId"),
                    "association_count": len(
                        network_acl.get(
                            "Associations",
                            [],
                        )
                    ),
                    "is_default": bool(
                        network_acl.get(
                            "IsDefault",
                            False,
                        )
                    ),
                }
            )

        return normalized

    def _get_network_acls(self) -> list[dict[str, Any]]:
        if self._network_acls_cache is None:
            self._network_acls_cache = (
                self.service.describe_network_acls()
            )

        return self._network_acls_cache

    def _get_client_vpn_endpoints(self) -> list[dict[str, Any]]:
        if self._client_vpn_endpoints_cache is None:
            self._client_vpn_endpoints_cache = (
                self.service.describe_client_vpn_endpoints()
            )

        return self._client_vpn_endpoints_cache

    def _get_vpn_connections(self) -> list[dict[str, Any]]:
        if self._vpn_connections_cache is None:
            self._vpn_connections_cache = (
                self.service.describe_vpn_connections()
            )

        return self._vpn_connections_cache

    def _get_spot_fleet_requests(self) -> list[dict[str, Any]]:
        if self._spot_fleet_requests_cache is None:
            self._spot_fleet_requests_cache = (
                self.service.describe_spot_fleet_requests()
            )

        return self._spot_fleet_requests_cache

    def _get_network_interfaces(self) -> list[dict[str, Any]]:
        if self._network_interfaces_cache is None:
            self._network_interfaces_cache = (
                self.service.describe_network_interfaces()
            )

        return self._network_interfaces_cache

    def collect_client_vpn_logging_coverage(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for endpoint in self._get_client_vpn_endpoints():
            endpoint_id = endpoint.get("ClientVpnEndpointId")

            if not endpoint_id:
                continue

            log_options = endpoint.get(
                "ConnectionLogOptions",
                {},
            )

            normalized.append(
                {
                    "endpoint_id": endpoint_id,
                    "vpc_id": endpoint.get("VpcId"),
                    "connection_log_enabled": bool(
                        log_options.get("Enabled", False)
                    ),
                }
            )

        return normalized

    @staticmethod
    def _vpn_tunnel_log_enabled(
        tunnel: dict[str, Any],
    ) -> bool:
        log_options = tunnel.get("LogOptions", {})
        cloudwatch = log_options.get(
            "CloudwatchLogOptions",
            {},
        )

        return bool(cloudwatch.get("LogEnabled", False))

    @staticmethod
    def _vpn_tunnel_ike_versions(
        tunnel: dict[str, Any],
    ) -> list[str]:
        versions = tunnel.get("IkeVersions", [])

        normalized: list[str] = []

        for version in versions:
            if isinstance(version, dict):
                value = version.get("Value")
            else:
                value = version

            if value:
                normalized.append(str(value).lower())

        return normalized

    def _vpn_tunnel_options(
        self,
        connection: dict[str, Any],
    ) -> list[dict[str, Any]]:
        options = connection.get(
            "VgwTelemetry",
        )

        if options:
            return []

        return connection.get(
            "Options",
            {},
        ).get(
            "TunnelOptions",
            [],
        )

    def collect_vpn_logging_coverage(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for connection in self._get_vpn_connections():
            connection_id = connection.get("VpnConnectionId")

            if not connection_id:
                continue

            tunnels = connection.get(
                "Options",
                {},
            ).get(
                "TunnelOptions",
                [],
            )

            log_statuses = [
                self._vpn_tunnel_log_enabled(tunnel)
                for tunnel in tunnels[:2]
            ]

            while len(log_statuses) < 2:
                log_statuses.append(False)

            normalized.append(
                {
                    "vpn_connection_id": connection_id,
                    "tunnel_1_logging_enabled": log_statuses[0],
                    "tunnel_2_logging_enabled": log_statuses[1],
                }
            )

        return normalized

    def collect_spot_fleet_ebs_encryption_coverage(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for fleet in self._get_spot_fleet_requests():
            fleet_id = fleet.get("SpotFleetRequestId")

            if not fleet_id:
                continue

            config = fleet.get(
                "SpotFleetRequestConfig",
                {},
            )

            launch_specs = config.get(
                "LaunchSpecifications",
                [],
            )

            launch_template_configs = config.get(
                "LaunchTemplateConfigs",
                [],
            )

            has_launch_parameters = bool(
                launch_specs or launch_template_configs
            )

            unencrypted_volume_count = 0
            ebs_volume_count = 0

            for specification in launch_specs:
                for mapping in specification.get(
                    "BlockDeviceMappings",
                    [],
                ):
                    ebs = mapping.get("Ebs")

                    if not ebs:
                        continue

                    ebs_volume_count += 1

                    if ebs.get("Encrypted") is not True:
                        unencrypted_volume_count += 1

            normalized.append(
                {
                    "spot_fleet_request_id": fleet_id,
                    "launch_parameters_present": has_launch_parameters,
                    "ebs_volume_count": ebs_volume_count,
                    "unencrypted_volume_count": (
                        unencrypted_volume_count
                    ),
                }
            )

        return normalized

    def collect_eni_source_destination_check_coverage(
        self,
    ) -> list[dict[str, Any]]:
        managed_types = {
            "aws_codestar_connections_managed",
            "branch",
            "efa",
            "interface",
            "lambda",
            "quicksight",
        }

        normalized: list[dict[str, Any]] = []

        for interface in self._get_network_interfaces():
            interface_id = interface.get("NetworkInterfaceId")

            if not interface_id:
                continue

            interface_type = str(
                interface.get("InterfaceType", "interface")
            ).lower()

            if interface_type not in managed_types:
                continue

            normalized.append(
                {
                    "network_interface_id": interface_id,
                    "interface_type": interface_type,
                    "source_dest_check": interface.get(
                        "SourceDestCheck",
                        True,
                    ),
                    "vpc_id": interface.get("VpcId"),
                    "subnet_id": interface.get("SubnetId"),
                }
            )

        return normalized

    def collect_vpn_ikev2_coverage(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for connection in self._get_vpn_connections():
            connection_id = connection.get("VpnConnectionId")

            if not connection_id:
                continue

            tunnels = connection.get(
                "Options",
                {},
            ).get(
                "TunnelOptions",
                [],
            )

            versions = [
                self._vpn_tunnel_ike_versions(tunnel)
                for tunnel in tunnels[:2]
            ]

            while len(versions) < 2:
                versions.append([])

            normalized.append(
                {
                    "vpn_connection_id": connection_id,
                    "tunnel_1_ike_versions": versions[0],
                    "tunnel_2_ike_versions": versions[1],
                }
            )

        return normalized


    def collect_vpcs(self) -> list[dict[str, Any]]:
        normalized = []

        for vpc in self._get_vpcs():
            vpc_id = vpc.get("VpcId")

            if not vpc_id:
                continue

            normalized.append(
                {
                    "vpc_id": vpc_id,
                    "cidr_block": vpc.get("CidrBlock"),
                    "state": vpc.get("State"),
                    "is_default": vpc.get("IsDefault", False),
                    "instance_tenancy": vpc.get(
                        "InstanceTenancy"
                    ),
                    "dhcp_options_id": vpc.get(
                        "DhcpOptionsId"
                    ),
                    "internet_gateway_block_mode": (
                        vpc.get(
                            "BlockPublicAccessStates",
                            {},
                        ).get(
                            "InternetGatewayBlockMode"
                        )
                    ),
                }
            )

        return normalized

    def collect_internet_gateways(self) -> list[dict[str, Any]]:
        normalized = []

        for gateway in self._get_internet_gateways():
            gateway_id = gateway.get("InternetGatewayId")

            if not gateway_id:
                continue

            attachments = gateway.get("Attachments", [])

            if not attachments:
                normalized.append(
                    {
                        "internet_gateway_id": gateway_id,
                        "vpc_id": None,
                        "state": "detached",
                    }
                )
                continue

            for attachment in attachments:
                normalized.append(
                    {
                        "internet_gateway_id": gateway_id,
                        "vpc_id": attachment.get("VpcId"),
                        "state": attachment.get("State"),
                    }
                )

        return normalized

    def collect_default_security_groups(self) -> list[dict[str, Any]]:
        normalized = []

        for security_group in self._get_default_security_groups():
            group_id = security_group.get("GroupId")
            vpc_id = security_group.get("VpcId")

            if not group_id or not vpc_id:
                continue

            normalized.append(
                {
                    "group_id": group_id,
                    "vpc_id": vpc_id,
                    "group_name": security_group.get("GroupName"),
                    "inbound_rule_count": len(
                        security_group.get("IpPermissions", [])
                    ),
                    "outbound_rule_count": len(
                        security_group.get("IpPermissionsEgress", [])
                    ),
                }
            )

        return normalized

    def collect_flow_log_coverage(self) -> list[dict[str, Any]]:
        flow_logs_by_vpc: dict[str, list[dict[str, Any]]] = {}

        for flow_log in self._get_flow_logs():
            resource_id = flow_log.get("ResourceId")

            if not resource_id:
                continue

            flow_logs_by_vpc.setdefault(
                resource_id,
                [],
            ).append(flow_log)

        normalized = []

        for vpc in self._get_vpcs():
            vpc_id = vpc.get("VpcId")

            if not vpc_id:
                continue

            vpc_flow_logs = flow_logs_by_vpc.get(vpc_id, [])

            active_flow_logs = [
                flow_log
                for flow_log in vpc_flow_logs
                if str(
                    flow_log.get("FlowLogStatus", "")
                ).upper()
                == "ACTIVE"
            ]

            normalized.append(
                {
                    "vpc_id": vpc_id,
                    "flow_log_count": len(vpc_flow_logs),
                    "active_flow_log_count": len(active_flow_logs),
                    "flow_logging_enabled": bool(active_flow_logs),
                }
            )

        return normalized

    def collect_ec2_endpoint_coverage(self) -> list[dict[str, Any]]:
        """
        Normalize EC2 VPC endpoint coverage per VPC.

        Security Hub EC2.10 requires an Amazon EC2 endpoint for
        every VPC. Both the standard regional EC2 endpoint service
        name and the FIPS variant are treated as compliant.

        Example:
            com.amazonaws.us-east-1.ec2
            com.amazonaws.us-east-1.ec2-fips
        """
        vpcs = self._get_vpcs()
        endpoints = self._get_vpc_endpoints()

        region = getattr(
            self.service.ec2_client.meta,
            "region_name",
            None,
        )

        expected_service_names: set[str] = set()

        if region:
            expected_service_names.add(
                f"com.amazonaws.{region}.ec2"
            )
            expected_service_names.add(
                f"com.amazonaws.{region}.ec2-fips"
            )

        covered_vpcs: set[str] = set()

        for endpoint in endpoints:
            vpc_id = endpoint.get("VpcId")

            if not vpc_id:
                continue

            service_name = endpoint.get("ServiceName")

            if service_name in expected_service_names:
                covered_vpcs.add(vpc_id)

        normalized: list[dict[str, Any]] = []

        for vpc in vpcs:
            vpc_id = vpc.get("VpcId")

            if not vpc_id:
                continue

            normalized.append(
                {
                    "vpc_id": vpc_id,
                    "region": region,
                    "ec2_endpoint_enabled": (
                        vpc_id in covered_vpcs
                    ),
                }
            )

        return normalized

    def collect_required_endpoint_coverage(
        self,
        service_name: str,
    ) -> list[dict[str, Any]]:
        vpcs = self._get_vpcs()
        endpoints = self._get_vpc_endpoints()

        region = getattr(
            self.service.ec2_client.meta,
            "region_name",
            None,
        )

        covered_vpcs: set[str] = set()

        for endpoint in endpoints:
            vpc_id = endpoint.get("VpcId")

            if not vpc_id:
                continue

            if endpoint.get("ServiceName") != service_name:
                continue

            if str(
                endpoint.get(
                    "VpcEndpointType",
                    "",
                )
            ).lower() != "interface":
                continue

            covered_vpcs.add(vpc_id)

        normalized = []

        for vpc in vpcs:
            vpc_id = vpc.get("VpcId")

            if not vpc_id:
                continue

            normalized.append(
                {
                    "vpc_id": vpc_id,
                    "region": region,
                    "service_name": service_name,
                    "endpoint_type": "interface",
                    "endpoint_enabled": (
                        vpc_id in covered_vpcs
                    ),
                }
            )

        return normalized

    def collect_network_acls(self) -> list[dict[str, Any]]:
        normalized = []

        for network_acl in self._get_network_acls():
            network_acl_id = network_acl.get("NetworkAclId")
            vpc_id = network_acl.get("VpcId")

            if not network_acl_id or not vpc_id:
                continue

            for entry in network_acl.get("Entries", []):
                normalized.append(
                    {
                        "network_acl_id": network_acl_id,
                        "vpc_id": vpc_id,
                        "is_default": network_acl.get(
                            "IsDefault",
                            False,
                        ),
                        "rule_number": entry.get("RuleNumber"),
                        "egress": entry.get("Egress", False),
                        "rule_action": entry.get("RuleAction"),
                        "protocol": entry.get("Protocol"),
                        "cidr_block": entry.get("CidrBlock"),
                        "ipv6_cidr_block": entry.get(
                            "Ipv6CidrBlock"
                        ),
                        "from_port": (
                            entry.get("PortRange", {}).get("From")
                        ),
                        "to_port": (
                            entry.get("PortRange", {}).get("To")
                        ),
                    }
                )

        return normalized


def _vpc_tagging_records(
    resources: list[dict[str, Any]],
    id_key: str,
    resource_type: str,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

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
                "resource_id": resource_id,
                "resource_type": resource_type,
                "tags": tags,
            }
        )

    return normalized


def collect_ec2_eni_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    return _vpc_tagging_records(
        collector._get_network_interfaces(),
        "NetworkInterfaceId",
        "network_interface",
    )


def collect_ec2_igw_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    return _vpc_tagging_records(
        collector._get_internet_gateways(),
        "InternetGatewayId",
        "internet_gateway",
    )


def collect_ec2_nat_gateway_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    resources = collector.service.describe_nat_gateways()

    if not isinstance(resources, list):
        return []

    return _vpc_tagging_records(
        resources,
        "NatGatewayId",
        "nat_gateway",
    )


def collect_ec2_nacl_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    return _vpc_tagging_records(
        collector._get_network_acls(),
        "NetworkAclId",
        "network_acl",
    )


def collect_ec2_route_table_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    resources = collector.service.describe_route_tables()

    if not isinstance(resources, list):
        return []

    return _vpc_tagging_records(
        resources,
        "RouteTableId",
        "route_table",
    )


def collect_ec2_security_group_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    resources = collector.service.describe_default_security_groups()

    # Do not use only default SGs for EC2.43.
    # Fetching all SGs is required.
    resources = collector.service.ec2_client.get_paginator(
        "describe_security_groups"
    ).paginate()

    groups: list[dict[str, Any]] = []

    for page in resources:
        groups.extend(
            page.get("SecurityGroups", [])
        )

    return _vpc_tagging_records(
        groups,
        "GroupId",
        "security_group",
    )


def collect_ec2_subnet_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    return _vpc_tagging_records(
        collector._get_subnets(),
        "SubnetId",
        "subnet",
    )


def collect_ec2_vpc_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    return _vpc_tagging_records(
        collector._get_vpcs(),
        "VpcId",
        "vpc",
    )


def collect_ec2_flow_log_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    return _vpc_tagging_records(
        collector._get_flow_logs(),
        "FlowLogId",
        "vpc_flow_log",
    )


def collect_ec2_vpc_peering_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    resources = (
        collector.service
        .describe_vpc_peering_connections()
    )

    if not isinstance(resources, list):
        return []

    return _vpc_tagging_records(
        resources,
        "VpcPeeringConnectionId",
        "vpc_peering_connection",
    )


def collect_ec2_vpn_gateway_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    resources = collector.service.describe_vpn_gateways()

    if not isinstance(resources, list):
        return []

    return _vpc_tagging_records(
        resources,
        "VpnGatewayId",
        "vpn_gateway",
    )


def collect_ec2_transit_gateway_tagging(
    collector: VPCDataCollector,
) -> list[dict[str, Any]]:
    resources = (
        collector.service
        .describe_transit_gateways()
    )

    if not isinstance(resources, list):
        return []

    return _vpc_tagging_records(
        resources,
        "TransitGatewayId",
        "transit_gateway",
    )
