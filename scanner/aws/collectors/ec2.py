from typing import Any

from scanner.aws.services.ec2 import EC2Service


class EC2DataCollector:
    """
    Collects and normalizes EC2 data required by
    CloudSentinel security rules.

    This layer does not make security decisions.

    Instance discovery is cached for the lifetime of this
    collector instance so multiple rules do not trigger
    duplicate describe_instances API calls.
    """

    def __init__(self, service: EC2Service):
        self.service = service
        self._instances_cache: list[dict[str, Any]] | None = None
        self._security_groups_cache: list[dict[str, Any]] | None = None

    def _get_instances(self) -> list[dict[str, Any]]:
        """
        Return discovered EC2 instances.

        The first call fetches instances from AWS and caches
        the result. Later calls reuse the cached data.
        """

        if self._instances_cache is None:
            self._instances_cache = self.service.describe_instances()

        return self._instances_cache

    def _get_security_groups(self) -> list[dict[str, Any]]:
        """
        Return all discovered security groups in the current
        AWS region.

        Security-group discovery is independent of EC2
        instance discovery so security groups are still
        scanned when the account has zero EC2 instances.
        """

        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_all_security_groups()
            )

        return self._security_groups_cache

    def collect_instances(self) -> list[dict[str, Any]]:
        instances = self._get_instances()

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

        instances = self._get_instances()

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

        if not volume_ids:
            return []

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
        Collect all security groups in the current AWS region.

        Security-group discovery does not depend on EC2 instances
        being present.
        """

        return self._get_security_groups()

    def collect_snapshots(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect EBS snapshots owned by the current AWS account
        and normalize their public-access status.
        """

        snapshots = self.service.describe_snapshots()

        collected_snapshots: list[dict[str, Any]] = []

        for snapshot in snapshots:
            snapshot_id = snapshot.get("SnapshotId")

            if not snapshot_id:
                continue

            collected_snapshots.append(
                {
                    "snapshot_id": snapshot_id,
                    "volume_id": snapshot.get("VolumeId"),
                    "state": snapshot.get("State"),
                    "public": snapshot.get("Public", False),
                }
            )

        return collected_snapshots
