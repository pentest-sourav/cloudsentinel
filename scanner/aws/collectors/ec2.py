from typing import Any

from scanner.aws.services.ec2 import EC2Service


class EC2DataCollector:
    """
    Collects and normalizes EC2 data required by
    CloudSentinel security rules.

    This layer does not make security decisions.
    """

    def __init__(self, service: EC2Service):
        self.service = service

    def collect_instances(self) -> list[dict[str, Any]]:
        instances = self.service.describe_instances()

        collected_instances: list[dict[str, Any]] = []

        for instance in instances:
            security_groups = instance.get(
                "SecurityGroups",
                [],
            )

            security_group_ids = [
                group["GroupId"]
                for group in security_groups
                if "GroupId" in group
            ]

            collected_instances.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "instance_state": (
                        instance.get("State", {}).get("Name")
                    ),
                    "security_group_ids": security_group_ids,
                    "public_ip": instance.get("PublicIpAddress"),
                    "private_ip": instance.get("PrivateIpAddress"),
                }
            )

        return collected_instances

    def collect_security_groups(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect all security groups attached to discovered
        EC2 instances.

        Security-group IDs are deduplicated before the AWS API
        request to avoid unnecessary calls.
        """

        instances = self.service.describe_instances()

        group_ids: set[str] = set()

        for instance in instances:
            for group in instance.get(
                "SecurityGroups",
                [],
            ):
                group_id = group.get("GroupId")

                if group_id:
                    group_ids.add(group_id)

        return self.service.describe_security_groups(
            sorted(group_ids)
        )
