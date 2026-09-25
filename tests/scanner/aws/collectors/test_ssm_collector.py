from unittest.mock import Mock

from scanner.aws.collectors.ssm import (
    SSMDataCollector,
)


def test_collect_ec2_management_correlates_running_and_stopped():
    service = Mock()

    service.describe_ec2_instances.return_value = [
        {
            "InstanceId": "i-running",
            "State": {"Name": "running"},
        },
        {
            "InstanceId": "i-stopped",
            "State": {"Name": "stopped"},
        },
        {
            "InstanceId": "i-terminated",
            "State": {"Name": "terminated"},
        },
    ]

    service.describe_managed_instances.return_value = [
        {
            "InstanceId": "i-running",
        }
    ]

    collector = SSMDataCollector(service)

    result = collector.collect_ec2_management()

    assert result == [
        {
            "resource_id": "i-running",
            "instance_id": "i-running",
            "instance_state": "running",
            "managed_by_ssm": True,
        },
        {
            "resource_id": "i-stopped",
            "instance_id": "i-stopped",
            "instance_state": "stopped",
            "managed_by_ssm": False,
        },
    ]


def test_collect_ec2_management_caches_api_calls():
    service = Mock()

    service.describe_ec2_instances.return_value = [
        {
            "InstanceId": "i-001",
            "State": {"Name": "running"},
        }
    ]

    service.describe_managed_instances.return_value = [
        {
            "InstanceId": "i-001",
        }
    ]

    collector = SSMDataCollector(service)

    collector.collect_ec2_management()
    collector.collect_ec2_management()

    service.describe_ec2_instances.assert_called_once()
    service.describe_managed_instances.assert_called_once()


def test_collect_compliance_normalizes_patch_and_association():
    service = Mock()

    service.list_resource_compliance_summaries.return_value = [
        {
            "ResourceId": "i-001",
            "ResourceType": "ManagedInstance",
            "ComplianceType": "Patch",
            "Status": "NON_COMPLIANT",
            "OverallSeverity": "HIGH",
            "ExecutionSummary": {
                "ExecutionTime": "2026-09-25T00:00:00Z"
            },
        },
        {
            "ResourceId": "i-001",
            "ResourceType": "ManagedInstance",
            "ComplianceType": "Association",
            "Status": "COMPLIANT",
        },
    ]

    collector = SSMDataCollector(service)

    result = collector.collect_compliance()

    assert result[0]["resource_id"] == "i-001"
    assert result[0]["compliance_type"] == "Patch"
    assert result[0]["status"] == "NON_COMPLIANT"

    assert result[1]["compliance_type"] == "Association"
    assert result[1]["status"] == "COMPLIANT"


def test_collect_document_permissions_detects_public_document():
    service = Mock()

    service.list_self_owned_documents.return_value = [
        {
            "Name": "PublicDocument",
            "Owner": "123456789012",
        }
    ]

    service.describe_document_permission.return_value = {
        "AccountIds": ["All"]
    }

    collector = SSMDataCollector(service)

    result = collector.collect_document_permissions()

    assert result == [
        {
            "resource_id": "PublicDocument",
            "document_name": "PublicDocument",
            "owner": "123456789012",
            "account_ids": ["All"],
            "public": True,
        }
    ]


def test_collect_automation_logging():
    service = Mock()

    service.get_service_setting.return_value = {
        "ServiceSetting": {
            "SettingId": (
                "/ssm/automation/"
                "customer-script-log-destination"
            ),
            "SettingValue": "CloudWatch",
            "Status": "Customized",
        }
    }

    collector = SSMDataCollector(service)

    result = collector.collect_automation_logging()

    assert result[0]["setting_value"] == "CloudWatch"
    assert result[0]["status"] == "Customized"


def test_collect_public_sharing_setting():
    service = Mock()

    service.get_service_setting.return_value = {
        "ServiceSetting": {
            "SettingId": (
                "/ssm/documents/console/"
                "public-sharing-permission"
            ),
            "SettingValue": "Disable",
            "Status": "Customized",
        }
    }

    collector = SSMDataCollector(service)

    result = (
        collector.collect_public_sharing_setting()
    )

    assert result[0]["setting_value"] == "Disable"
    assert result[0]["status"] == "Customized"
