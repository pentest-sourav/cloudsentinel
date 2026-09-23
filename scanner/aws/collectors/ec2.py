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

        self._instances_cache: list[dict[str, Any]] | None = None
        self._security_groups_cache: list[dict[str, Any]] | None = None
        self._ebs_default_encryption_cache: bool | None = None
        self._addresses_cache: list[dict[str, Any]] | None = None

    def _get_instances(self) -> list[dict[str, Any]]:
        if self._instances_cache is None:
            self._instances_cache = self.service.describe_instances()

        return self._instances_cache

    def _get_security_groups(self) -> list[dict[str, Any]]:
        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_all_security_groups()
            )

        return self._security_groups_cache

    def collect_instances(self) -> list[dict[str, Any]]:
        """
        Collect the stable EC2 instance data contract used by the
        existing EC2 rules.

        Extended instance attributes used by newer rules are exposed
        through collect_extended_instances() so existing consumers
        are not forced to handle additional fields.
        """
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
                        instance.get(
                            "State",
                            {},
                        ).get("Name")
                    ),
                    "security_group_ids": security_group_ids,
                    "public_ip": instance.get(
                        "PublicIpAddress"
                    ),
                    "private_ip": instance.get(
                        "PrivateIpAddress"
                    ),
                    "metadata_http_tokens": (
                        instance.get(
                            "MetadataOptions",
                            {},
                        ).get("HttpTokens")
                    ),
                }
            )

        return collected_instances

    def collect_extended_instances(self) -> list[dict[str, Any]]:
        """
        Collect additional EC2 instance attributes required by
        extended security controls.

        This intentionally remains separate from collect_instances()
        so the original collector contract remains stable.
        """
        instances = self._get_instances()

        collected_instances: list[dict[str, Any]] = []

        for instance in instances:
            network_interfaces = instance.get(
                "NetworkInterfaces",
                [],
            )

            collected_instances.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "instance_state": (
                        instance.get(
                            "State",
                            {},
                        ).get("Name")
                    ),
                    "network_interface_count": len(
                        network_interfaces
                    ),
                    "virtualization_type": instance.get(
                        "VirtualizationType"
                    ),
                    "launch_time": instance.get(
                        "LaunchTime"
                    ),
                    "state_transition_reason": instance.get(
                        "StateTransitionReason"
                    ),
                }
            )

        return collected_instances

    def collect_ebs_volumes(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect EBS volumes attached to discovered EC2
        instances and normalize encryption status.
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
                    "encrypted": encryption_by_volume_id[
                        volume_id
                    ],
                }
            )

        return collected_volumes

    def collect_security_groups(
        self,
    ) -> list[dict[str, Any]]:
        return self._get_security_groups()

    def collect_snapshots(
        self,
    ) -> list[dict[str, Any]]:
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

    def collect_ebs_default_encryption(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect regional EBS encryption-by-default status.

        Returned as a single record so it can use the generic
        RuleExecutor collection model.
        """
        if self._ebs_default_encryption_cache is None:
            self._ebs_default_encryption_cache = (
                self.service.get_ebs_encryption_by_default()
            )

        return [
            {
                "ebs_encryption_by_default": (
                    self._ebs_default_encryption_cache
                )
            }
        ]

    def collect_elastic_ips(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect Elastic IP allocation and association state.

        The collector treats a non-list service result as an empty
        collection. This preserves the collector contract when a
        mocked or alternate service implementation does not provide
        Elastic IP data, while the real EC2 service always returns
        a list.
        """
        if self._addresses_cache is None:
            addresses = self.service.describe_addresses()

            if not isinstance(addresses, list):
                self._addresses_cache = []
            else:
                self._addresses_cache = addresses

        collected_addresses: list[dict[str, Any]] = []

        for address in self._addresses_cache:
            allocation_id = address.get("AllocationId")

            if not allocation_id:
                continue

            instance_id = address.get("InstanceId")
            network_interface_id = address.get(
                "NetworkInterfaceId"
            )

            collected_addresses.append(
                {
                    "allocation_id": allocation_id,
                    "public_ip": address.get("PublicIp"),
                    "instance_id": instance_id,
                    "network_interface_id": (
                        network_interface_id
                    ),
                    "associated": bool(
                        instance_id
                        or network_interface_id
                    ),
                }
            )

        return collected_addresses
