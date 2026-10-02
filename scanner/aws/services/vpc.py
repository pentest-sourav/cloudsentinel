from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class VPCService:
    """
    Read-only AWS VPC discovery service.

    This service is responsible only for collecting VPC,
    Internet Gateway, default Security Group, VPC Flow Log,
    and Network ACL configuration data.
    """

    def __init__(self, session):
        self.session = session
        self.ec2_client = create_aws_client(session, "ec2")

    def describe_vpcs(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator("describe_vpcs")

            vpcs = []

            for page in paginator.paginate():
                vpcs.extend(page.get("Vpcs", []))

            return vpcs

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"VPC discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during VPC discovery: {exc}"
            ) from exc

    def describe_internet_gateways(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_internet_gateways"
            )

            internet_gateways = []

            for page in paginator.paginate():
                internet_gateways.extend(
                    page.get("InternetGateways", [])
                )

            return internet_gateways

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Internet Gateway discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Internet Gateway discovery: "
                f"{exc}"
            ) from exc

    def describe_default_security_groups(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_security_groups"
            )

            security_groups = []

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "group-name",
                        "Values": ["default"],
                    }
                ]
            ):
                security_groups.extend(
                    page.get("SecurityGroups", [])
                )

            return security_groups

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Default Security Group discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Default Security Group discovery: "
                f"{exc}"
            ) from exc

    def describe_flow_logs(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_flow_logs"
            )

            flow_logs = []

            for page in paginator.paginate():
                flow_logs.extend(page.get("FlowLogs", []))

            return flow_logs

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"VPC Flow Log discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during VPC Flow Log discovery: "
                f"{exc}"
            ) from exc

    def describe_subnets(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_subnets"
            )

            subnets: list[dict[str, Any]] = []

            for page in paginator.paginate():
                subnets.extend(
                    page.get("Subnets", [])
                )

            return subnets

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"Subnet discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during subnet discovery: {exc}"
            ) from exc

    def describe_vpc_block_public_access_options(
        self,
    ) -> dict[str, Any]:
        """
        Return the regional VPC Block Public Access configuration.

        AWS exposes VPC BPA configuration through a dedicated EC2 API.
        This is account/Region-level configuration rather than a
        per-VPC resource.
        """
        try:
            response = (
                self.ec2_client
                .describe_vpc_block_public_access_options()
            )

            return response.get(
                "VpcBlockPublicAccessOptions",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"VPC Block Public Access discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during VPC Block Public Access "
                f"discovery: {exc}"
            ) from exc

    def describe_vpc_endpoints(self) -> list[dict[str, Any]]:
        """
        Return all VPC endpoints in the current AWS account/region.

        AWS API access remains isolated to the service layer.
        Security evaluation is performed by the collector/rule layers.
        """
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_vpc_endpoints"
            )

            endpoints: list[dict[str, Any]] = []

            for page in paginator.paginate():
                endpoints.extend(
                    page.get("VpcEndpoints", [])
                )

            return endpoints

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"VPC endpoint discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during VPC endpoint discovery: "
                f"{exc}"
            ) from exc

    def describe_client_vpn_endpoints(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_client_vpn_endpoints"
            )

            endpoints: list[dict[str, Any]] = []

            for page in paginator.paginate():
                endpoints.extend(
                    page.get("ClientVpnEndpoints", [])
                )

            return endpoints

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Client VPN endpoint discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Client VPN endpoint discovery: "
                f"{exc}"
            ) from exc

    def describe_vpn_connections(self) -> list[dict[str, Any]]:
        try:
            vpn_connections: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                kwargs: dict[str, Any] = {}

                if next_token:
                    kwargs["NextToken"] = next_token

                response = self.ec2_client.describe_vpn_connections(
                    **kwargs
                )

                entries = response.get(
                    "VpnConnections",
                    [],
                )

                if isinstance(entries, list):
                    vpn_connections.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                    or token == next_token
                ):
                    break

                next_token = token

            return vpn_connections

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                "VPC VPN connection discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during VPC VPN connection "
                f"discovery: {exc}"
            ) from exc

    def describe_spot_fleet_requests(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_spot_fleet_requests"
            )

            fleets: list[dict[str, Any]] = []

            for page in paginator.paginate():
                fleets.extend(
                    page.get("SpotFleetRequestConfigs", [])
                )

            return fleets

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Spot Fleet discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Spot Fleet discovery: "
                f"{exc}"
            ) from exc

    def describe_network_interfaces(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_network_interfaces"
            )

            interfaces: list[dict[str, Any]] = []

            for page in paginator.paginate():
                interfaces.extend(
                    page.get("NetworkInterfaces", [])
                )

            return interfaces

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Network interface discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during network interface discovery: "
                f"{exc}"
            ) from exc


    def describe_network_acls(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_network_acls"
            )

            network_acls = []

            for page in paginator.paginate():
                network_acls.extend(
                    page.get("NetworkAcls", [])
                )

            return network_acls

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Network ACL discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Network ACL discovery: "
                f"{exc}"
            ) from exc


def _describe_vpc_tagging_resources(
    self,
    operation_name: str,
    result_key: str,
    error_name: str,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    try:
        paginator = self.ec2_client.get_paginator(
            operation_name
        )

        resources: list[dict[str, Any]] = []

        for page in paginator.paginate(**kwargs):
            entries = page.get(result_key, [])

            if isinstance(entries, list):
                resources.extend(
                    entry
                    for entry in entries
                    if isinstance(entry, dict)
                )

        return resources

    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "UnknownError")
        message = error.get(
            "Message",
            "AWS request failed",
        )

        raise RuntimeError(
            f"{error_name} discovery failed: "
            f"{code}: {message}"
        ) from exc

    except BotoCoreError as exc:
        raise RuntimeError(
            f"AWS SDK error during {error_name} discovery: "
            f"{exc}"
        ) from exc


def describe_nat_gateways(
    self,
) -> list[dict[str, Any]]:
    return _describe_vpc_tagging_resources(
        self,
        "describe_nat_gateways",
        "NatGateways",
        "NAT gateway",
    )


def describe_route_tables(
    self,
) -> list[dict[str, Any]]:
    return _describe_vpc_tagging_resources(
        self,
        "describe_route_tables",
        "RouteTables",
        "route table",
    )


def describe_vpc_peering_connections(
    self,
) -> list[dict[str, Any]]:
    return _describe_vpc_tagging_resources(
        self,
        "describe_vpc_peering_connections",
        "VpcPeeringConnections",
        "VPC peering connection",
    )


def describe_vpn_gateways(
    self,
) -> list[dict[str, Any]]:
    return _describe_vpc_tagging_resources(
        self,
        "describe_vpn_gateways",
        "VpnGateways",
        "VPN gateway",
    )


def describe_transit_gateways(
    self,
) -> list[dict[str, Any]]:
    return _describe_vpc_tagging_resources(
        self,
        "describe_transit_gateways",
        "TransitGateways",
        "transit gateway",
    )


VPCService.describe_nat_gateways = describe_nat_gateways
VPCService.describe_route_tables = describe_route_tables
VPCService.describe_vpc_peering_connections = (
    describe_vpc_peering_connections
)
VPCService.describe_vpn_gateways = describe_vpn_gateways
VPCService.describe_transit_gateways = (
    describe_transit_gateways
)
