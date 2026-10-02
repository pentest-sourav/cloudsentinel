from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.session import AWS_RETRY_CONFIG


class EC2Service:
    """
    Read-only AWS EC2 service layer.

    Responsible only for retrieving EC2, security-group,
    EBS, Elastic IP, Launch Template, and related configuration
    from AWS.

    Security analysis belongs in collectors/rules, not here.
    """

    ID_BATCH_SIZE = 100

    def __init__(self, session):
        self.session = session
        self.ec2_client = session.client(
            "ec2",
            config=AWS_RETRY_CONFIG,
        )

    @staticmethod
    def _chunks(
        items: list[str],
        size: int,
    ):
        for index in range(0, len(items), size):
            yield items[index:index + size]

    def _describe_tagging_resources(
        self,
        operation: str,
        result_key: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                operation
            )

            resources: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    result_key,
                    [],
                )

                if isinstance(entries, list):
                    resources.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return resources

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
                f"{operation} discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during {operation} discovery: "
                f"{exc}"
            ) from exc

    def describe_instances(
        self,
    ) -> list[dict[str, Any]]:
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
                    if not isinstance(reservation, dict):
                        continue

                    entries = reservation.get(
                        "Instances",
                        [],
                    )

                    if isinstance(entries, list):
                        instances.extend(
                            entry
                            for entry in entries
                            if isinstance(entry, dict)
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
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_security_groups"
            )

            security_groups: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    "SecurityGroups",
                    [],
                )

                if isinstance(entries, list):
                    security_groups.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
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

    def describe_all_volumes(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_volumes",
            "Volumes",
        )

    def describe_snapshots(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_snapshots"
            )

            snapshots: list[dict[str, Any]] = []

            for page in paginator.paginate(
                OwnerIds=["self"],
            ):
                entries = page.get(
                    "Snapshots",
                    [],
                )

                if isinstance(entries, list):
                    snapshots.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
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

    def get_ebs_encryption_by_default(
        self,
    ) -> bool:
        try:
            response = (
                self.ec2_client
                .get_ebs_encryption_by_default()
            )

            return bool(
                response.get(
                    "EbsEncryptionByDefault",
                    False,
                )
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
                f"EBS encryption-default discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during EBS encryption-default "
                f"discovery: {exc}"
            ) from exc

    def describe_addresses(
        self,
    ) -> list[dict[str, Any]]:
        try:
            response = self.ec2_client.describe_addresses()

            addresses = response.get(
                "Addresses",
                [],
            )

            if not isinstance(addresses, list):
                return []

            return [
                address
                for address in addresses
                if isinstance(address, dict)
            ]

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
                f"Elastic IP discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during Elastic IP discovery: "
                f"{exc}"
            ) from exc

    def describe_launch_templates(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_launch_templates"
            )

            launch_templates: list[dict[str, Any]] = []

            for page in paginator.paginate():
                entries = page.get(
                    "LaunchTemplates",
                    [],
                )

                if isinstance(entries, list):
                    launch_templates.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return launch_templates

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
                f"EC2 launch-template discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during EC2 launch-template "
                f"discovery: {exc}"
            ) from exc

    def describe_default_launch_template_versions(
        self,
        launch_template_id: str,
    ) -> list[dict[str, Any]]:
        if not launch_template_id:
            return []

        try:
            paginator = self.ec2_client.get_paginator(
                "describe_launch_template_versions"
            )

            versions: list[dict[str, Any]] = []

            for page in paginator.paginate(
                LaunchTemplateId=launch_template_id,
                Versions=["$Default"],
            ):
                entries = page.get(
                    "LaunchTemplateVersions",
                    [],
                )

                if isinstance(entries, list):
                    versions.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return versions

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
                "EC2 launch-template version discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during EC2 launch-template version "
                f"discovery: {exc}"
            ) from exc

    def get_snapshot_block_public_access_state(
        self,
    ) -> dict[str, Any]:
        try:
            response = (
                self.ec2_client
                .get_snapshot_block_public_access_state()
            )

            return {
                "state": response.get("State"),
                "managed_by": response.get("ManagedBy"),
            }

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
                "EBS snapshot Block Public Access discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during EBS snapshot Block Public "
                f"Access discovery: {exc}"
            ) from exc

    def describe_network_interfaces(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_network_interfaces",
            "NetworkInterfaces",
        )

    def describe_vpcs(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_vpcs",
            "Vpcs",
        )

    def describe_subnets(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_subnets",
            "Subnets",
        )

    def describe_internet_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_internet_gateways",
            "InternetGateways",
        )

    def describe_nat_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_nat_gateways",
            "NatGateways",
        )

    def describe_network_acls(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_network_acls",
            "NetworkAcls",
        )

    def describe_route_tables(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_route_tables",
            "RouteTables",
        )

    def describe_flow_logs(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_flow_logs",
            "FlowLogs",
        )

    def describe_vpc_peering_connections(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_vpc_peering_connections",
            "VpcPeeringConnections",
        )

    def describe_vpn_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_vpn_gateways",
            "VpnGateways",
        )

    def describe_transit_gateways(
        self,
    ) -> list[dict[str, Any]]:
        return self._describe_tagging_resources(
            "describe_transit_gateways",
            "TransitGateways",
        )
