
from typing import Any

from scanner.aws.services.ssm import SSMService


class SSMDataCollector:
    """
    Collect and normalize AWS Systems Manager data.

    AWS API responses are cached for the duration of a scan.
    """

    def __init__(
        self,
        service: SSMService,
    ):
        self.service = service

        self._ec2_instances_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._managed_instances_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._compliance_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._documents_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._document_permissions_cache: (
            dict[str, dict[str, Any]]
        ) = {}

        self._settings_cache: (
            dict[str, dict[str, Any]]
        ) = {}

    def _get_ec2_instances(
        self,
    ) -> list[dict[str, Any]]:
        if self._ec2_instances_cache is None:
            self._ec2_instances_cache = (
                self.service.describe_ec2_instances()
            )

        return self._ec2_instances_cache

    def _get_managed_instances(
        self,
    ) -> list[dict[str, Any]]:
        if self._managed_instances_cache is None:
            self._managed_instances_cache = (
                self.service.describe_managed_instances()
            )

        return self._managed_instances_cache

    def _get_compliance_summaries(
        self,
    ) -> list[dict[str, Any]]:
        if self._compliance_cache is None:
            self._compliance_cache = (
                self.service.list_resource_compliance_summaries()
            )

        return self._compliance_cache

    def _get_documents(
        self,
    ) -> list[dict[str, Any]]:
        if self._documents_cache is None:
            self._documents_cache = (
                self.service.list_self_owned_documents()
            )

        return self._documents_cache

    def _get_document_permission(
        self,
        document_name: str,
    ) -> dict[str, Any]:
        if document_name not in self._document_permissions_cache:
            self._document_permissions_cache[
                document_name
            ] = self.service.describe_document_permission(
                document_name
            )

        return self._document_permissions_cache[
            document_name
        ]

    def _get_setting(
        self,
        setting_id: str,
    ) -> dict[str, Any]:
        if setting_id not in self._settings_cache:
            self._settings_cache[
                setting_id
            ] = self.service.get_service_setting(
                setting_id
            )

        return self._settings_cache[setting_id]

    def collect_ec2_management(
        self,
    ) -> list[dict[str, Any]]:
        """
        Correlate all stopped/running EC2 instances with
        Systems Manager managed-instance information.

        DescribeInstanceInformation does not return stopped
        EC2 instances, so EC2 remains the authoritative
        inventory for SSM.1.
        """
        ec2_instances = self._get_ec2_instances()
        managed_instances = self._get_managed_instances()

        managed_ids = {
            item.get("InstanceId")
            for item in managed_instances
            if isinstance(
                item.get("InstanceId"),
                str,
            )
        }

        results: list[dict[str, Any]] = []

        for instance in ec2_instances:
            instance_id = instance.get("InstanceId")

            if not isinstance(instance_id, str):
                continue

            state = (
                instance.get(
                    "State",
                    {},
                ).get("Name")
                if isinstance(
                    instance.get("State"),
                    dict,
                )
                else None
            )

            if state not in {
                "running",
                "stopped",
            }:
                continue

            results.append(
                {
                    "resource_id": instance_id,
                    "instance_id": instance_id,
                    "instance_state": state,
                    "managed_by_ssm": (
                        instance_id in managed_ids
                    ),
                }
            )

        return results

    def collect_compliance(
        self,
    ) -> list[dict[str, Any]]:
        """
        Normalize SSM resource compliance summaries.

        The AWS response exposes ComplianceType and Status.
        Patch and Association compliance are evaluated separately.
        """
        normalized: list[dict[str, Any]] = []

        for item in self._get_compliance_summaries():
            resource_id = item.get(
                "ResourceId"
            )

            if not isinstance(resource_id, str):
                continue

            compliance_type = item.get(
                "ComplianceType"
            )

            if not isinstance(
                compliance_type,
                str,
            ):
                continue

            normalized.append(
                {
                    "resource_id": resource_id,
                    "resource_type": item.get(
                        "ResourceType"
                    ),
                    "compliance_type": compliance_type,
                    "status": item.get(
                        "Status"
                    ),
                    "overall_severity": item.get(
                        "OverallSeverity"
                    ),
                    "execution_summary": item.get(
                        "ExecutionSummary"
                    ),
                }
            )

        return normalized

    def collect_document_permissions(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for document in self._get_documents():
            name = document.get("Name")

            if not isinstance(name, str) or not name:
                continue

            permission = self._get_document_permission(
                name
            )

            account_ids = permission.get(
                "AccountIds",
                [],
            )

            if not isinstance(account_ids, list):
                account_ids = []

            account_ids = [
                account_id
                for account_id in account_ids
                if isinstance(account_id, str)
            ]

            normalized.append(
                {
                    "resource_id": name,
                    "document_name": name,
                    "owner": document.get(
                        "Owner"
                    ),
                    "account_ids": account_ids,
                    "public": (
                        "All" in account_ids
                    ),
                }
            )

        return normalized

    def collect_automation_logging(
        self,
    ) -> list[dict[str, Any]]:
        setting = self._get_setting(
            SSMService.AUTOMATION_LOG_DESTINATION_SETTING
        )

        service_setting = setting.get(
            "ServiceSetting",
            {},
        )

        if not isinstance(
            service_setting,
            dict,
        ):
            service_setting = {}

        return [
            {
                "resource_id": (
                    SSMService
                    .AUTOMATION_LOG_DESTINATION_SETTING
                ),
                "setting_id": service_setting.get(
                    "SettingId",
                    SSMService.AUTOMATION_LOG_DESTINATION_SETTING,
                ),
                "setting_value": service_setting.get(
                    "SettingValue"
                ),
                "status": service_setting.get(
                    "Status"
                ),
            }
        ]

    def collect_public_sharing_setting(
        self,
    ) -> list[dict[str, Any]]:
        setting = self._get_setting(
            SSMService.PUBLIC_SHARING_SETTING
        )

        service_setting = setting.get(
            "ServiceSetting",
            {},
        )

        if not isinstance(
            service_setting,
            dict,
        ):
            service_setting = {}

        return [
            {
                "resource_id": (
                    SSMService.PUBLIC_SHARING_SETTING
                ),
                "setting_id": service_setting.get(
                    "SettingId",
                    SSMService.PUBLIC_SHARING_SETTING,
                ),
                "setting_value": service_setting.get(
                    "SettingValue"
                ),
                "status": service_setting.get(
                    "Status"
                ),
            }
        ]

