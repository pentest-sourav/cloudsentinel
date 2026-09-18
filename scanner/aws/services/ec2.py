from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class EC2Service:
    """
    Read-only AWS EC2 service layer.

    Responsible only for retrieving EC2, security-group,
    EBS volume, and EBS snapshot configuration from AWS.

    Security analysis belongs to collectors/rules, not here.
    """

    ID_BATCH_SIZE = 100

    def __init__(self, session):
        self.session = session
        self.ec2_client = session.client("ec2")

    @staticmethod
    def _chunks(
        items: list[str],
        size: int,
    ):
        """
        Split a list into smaller batches.
        """

        for index in range(0, len(items), size):
            yield items[index:index + size]

    def describe_instances(self) -> list[dict[str, Any]]:
        """
        Retrieve all EC2 instances in the current AWS region.

        This operation is read-only.
        """

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
        """
        Retrieve specific EC2 security groups by ID.

        This method is retained for callers that need targeted
        security-group lookup.

        This operation is read-only.
        """

        if not group_ids:
            return []

        try:
            groups: list[dict[str, Any]] = []

            for batch in self._chunks(
                group_ids,
                self.ID_BATCH_SIZE,
            ):
                response = self.ec2_client.describe_security_groups(
                    GroupIds=batch,
                )

                groups.extend(
                    response.get(
                        "SecurityGroups",
                        [],
                    )
                )

            return groups

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

    def describe_all_security_groups(
        self,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all EC2 security groups in the current
        AWS region.

        This operation is read-only and does not depend on
        EC2 instances being present.
        """

        try:
            paginator = self.ec2_client.get_paginator(
                "describe_security_groups"
            )

            security_groups: list[dict[str, Any]] = []

            for page in paginator.paginate():
                security_groups.extend(
                    page.get(
                        "SecurityGroups",
                        [],
                    )
                )

            return security_groups

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
            volumes: list[dict[str, Any]] = []

            for batch in self._chunks(
                volume_ids,
                self.ID_BATCH_SIZE,
            ):
                response = self.ec2_client.describe_volumes(
                    VolumeIds=batch,
                )

                volumes.extend(
                    response.get(
                        "Volumes",
                        [],
                    )
                )

            return volumes

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

    def describe_snapshots(
        self,
    ) -> list[dict[str, Any]]:
        """
        Retrieve EBS snapshots owned by the current AWS account.

        This operation is read-only.
        """

        try:
            paginator = self.ec2_client.get_paginator(
                "describe_snapshots"
            )

            snapshots: list[dict[str, Any]] = []

            for page in paginator.paginate(
                OwnerIds=["self"],
            ):
                snapshots.extend(
                    page.get(
                        "Snapshots",
                        [],
                    )
                )

            return snapshots

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
                f"EBS snapshot discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during EBS snapshot discovery: "
                f"{exc}"
            ) from exc
