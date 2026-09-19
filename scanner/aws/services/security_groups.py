from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class SecurityGroupService:
    """
    Read-only AWS Security Group discovery service.

    This service is responsible only for collecting Security Group
    configuration data. Security evaluation is handled separately
    by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.ec2_client = session.client("ec2")

    def describe_security_groups(self) -> list[dict[str, Any]]:
        """
        Return all Security Groups available to the current AWS account.
        """
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
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"Security Group discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Security Group discovery: "
                f"{exc}"
            ) from exc
