from typing import Any

from scanner.aws.services.vpc import VPCService


class VPCDataCollector:
    """
    Normalizes AWS VPC, Internet Gateway, default Security Group,
    and VPC Flow Log configuration data for security rules.
    """

    def __init__(self, service: VPCService):
        self.service = service
        self._vpcs_cache: list[dict[str, Any]] | None = None
        self._internet_gateways_cache: list[dict[str, Any]] | None = None
        self._default_security_groups_cache: (
            list[dict[str, Any]] | None
        ) = None
        self._flow_logs_cache: list[dict[str, Any]] | None = None

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
