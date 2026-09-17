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
                    "metadata_http_tokens": (
                        instance.get(
                            "MetadataOptions",
                            {},
                        ).get("HttpTokens")
                    ),
                }
            )

        return collected_instances

    def collect_ebs_volumes(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect EBS volumes attached to discovered EC2 instances
        and normalize their encryption status.
        """

        instances = self.service.describe_instances()

        instance_volume_map: list[dict[str, str]] = []
        volume_ids: set[str] = set()

        for instance in instances:
            instance_id = instance.get("InstanceId")

            if not instance_id:
                continue

            for mapping in instance.get(
                "BlockDeviceMappings",
                [],
            ):
                ebs = mapping.get("Ebs", {})
                volume_id = ebs.get("VolumeId")

                if not volume_id:
                    continue

                instance_volume_map.append(
                    {
                        "instance_id": instance_id,
                        "volume_id": volume_id,
                    }
                )

                volume_ids.add(volume_id)

        volumes = self.service.describe_volumes(
            sorted(volume_ids)
        )

        encryption_by_volume_id = {
            volume.get("VolumeId"): volume.get("Encrypted")
            for volume in volumes
            if volume.get("VolumeId")
        }

        collected_volumes: list[dict[str, Any]] = []

        for mapping in instance_volume_map:
            volume_id = mapping["volume_id"]

            if volume_id not in encryption_by_volume_id:
                continue

            collected_volumes.append(
                {
                    "instance_id": mapping["instance_id"],
                    "volume_id": volume_id,
                    "encrypted": encryption_by_volume_id[volume_id],
                }
            )

        return collected_volumes

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
