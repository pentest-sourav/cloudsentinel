from typing import Any

from scanner.aws.services.vpc import VPCService


class VPCDataCollector:
    """
    Normalizes AWS VPC and Internet Gateway configuration
    data for security rules.
    """

    def __init__(self, service: VPCService):
        self.service = service
        self._vpcs_cache: list[dict[str, Any]] | None = None
        self._internet_gateways_cache: list[dict[str, Any]] | None = None

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
