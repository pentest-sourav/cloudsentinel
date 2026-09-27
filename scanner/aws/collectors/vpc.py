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

    def _get_network_acls(self) -> list[dict[str, Any]]:
        if self._network_acls_cache is None:
            self._network_acls_cache = (
                self.service.describe_network_acls()
            )

        return self._network_acls_cache

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
                    }
                )

        return normalized
