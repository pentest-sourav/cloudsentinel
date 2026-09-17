from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class EC2Service:
    """
    Read-only AWS EC2 service layer.

    Responsible only for retrieving EC2 and security-group
    configuration from AWS.

    Security analysis belongs to collectors/rules, not here.
    """

    def __init__(self, session):
        self.session = session
        self.ec2_client = session.client("ec2")

    def describe_instances(self) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_instances"
            )

            instances: list[dict[str, Any]] = []

            for page in paginator.paginate():
                for reservation in page.get(
                    "Reservations",
                    [],
                ):
                    instances.extend(
                        reservation.get(
                            "Instances",
                            [],
                        )
                    )

            return instances

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"EC2 instance discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during EC2 instance discovery: "
                f"{exc}"
            ) from exc

    def describe_security_groups(
        self,
        group_ids: list[str],
    ) -> list[dict[str, Any]]:
        if not group_ids:
            return []

        try:
            response = self.ec2_client.describe_security_groups(
                GroupIds=group_ids,
            )

            return response.get(
                "SecurityGroups",
                [],
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"EC2 security-group discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during EC2 security-group "
                f"discovery: {exc}"
            ) from exc

    def describe_volumes(
        self,
        volume_ids: list[str],
    ) -> list[dict[str, Any]]:
        """
        Retrieve EBS volume configuration for the supplied
        volume IDs.

        This operation is read-only.
        """

        if not volume_ids:
            return []

        try:
            response = self.ec2_client.describe_volumes(
                VolumeIds=volume_ids,
            )

            return response.get(
                "Volumes",
                [],
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"EBS volume discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during EBS volume discovery: "
                f"{exc}"
            ) from exc
