from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class SecurityGroupService:
    """
    Read-only AWS Security Group discovery service.
    """

    def __init__(self, session):
        self.session = session
        self.ec2_client = create_aws_client(session, "ec2")

    def describe_security_groups(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_security_groups"
            )

            security_groups = []

            for page in paginator.paginate():
                security_groups.extend(
                    page.get("SecurityGroups", [])
                )

            return security_groups

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Security Group discovery failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Security Group discovery: "
                f"{exc}"
            ) from exc

    def describe_network_interfaces(self) -> list[dict[str, Any]]:
        """
        Return all network interfaces and their attached
        Security Group identifiers.
        """
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_network_interfaces"
            )

            network_interfaces = []

            for page in paginator.paginate():
                network_interfaces.extend(
                    page.get("NetworkInterfaces", [])
                )

            return network_interfaces

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"Network Interface discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Network Interface discovery: "
                f"{exc}"
            ) from exc
