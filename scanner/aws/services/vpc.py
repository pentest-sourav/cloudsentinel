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
