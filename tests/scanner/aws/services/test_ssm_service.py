from unittest.mock import Mock

import pytest

from scanner.aws.services.ssm import SSMService


@pytest.fixture
def session():
    return Mock()


@pytest.fixture
def ssm_client():
    return Mock()


@pytest.fixture
def ec2_client():
    return Mock()


@pytest.fixture
def service(
    session,
    ssm_client,
    ec2_client,
    monkeypatch,
):
    def create_client(
        _session,
        service_name,
    ):
        if service_name == "ssm":
            return ssm_client

        if service_name == "ec2":
            return ec2_client

        raise AssertionError(
            f"Unexpected client: {service_name}"
        )

    monkeypatch.setattr(
        "scanner.aws.services.ssm.create_aws_client",
        create_client,
    )

    return SSMService(session)


def test_describe_ec2_instances_paginates(
    service,
    ec2_client,
):
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-001"},
                    ]
                }
            ]
        },
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-002"},
                    ]
                }
            ]
        },
    ]

    ec2_client.get_paginator.return_value = paginator

    result = service.describe_ec2_instances()

    assert result == [
        {"InstanceId": "i-001"},
        {"InstanceId": "i-002"},
    ]

    ec2_client.get_paginator.assert_called_once_with(
        "describe_instances"
    )


def test_describe_managed_instances_paginates(
    service,
    ssm_client,
):
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "InstanceInformationList": [
                {"InstanceId": "i-001"},
            ]
        },
        {
            "InstanceInformationList": [
                {"InstanceId": "i-002"},
            ]
        },
    ]

    ssm_client.get_paginator.return_value = paginator

    result = service.describe_managed_instances()

    assert result == [
        {"InstanceId": "i-001"},
        {"InstanceId": "i-002"},
    ]

    ssm_client.get_paginator.assert_called_once_with(
        "describe_instance_information"
    )


def test_list_resource_compliance_summaries(
    service,
    ssm_client,
):
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "ResourceComplianceSummaryItems": [
                {
                    "ResourceId": "i-001",
                    "ComplianceType": "Patch",
                    "Status": "COMPLIANT",
                }
            ]
        }
    ]

    ssm_client.get_paginator.return_value = paginator

    result = (
        service.list_resource_compliance_summaries()
    )

    assert result == [
        {
            "ResourceId": "i-001",
            "ComplianceType": "Patch",
            "Status": "COMPLIANT",
        }
    ]


def test_list_self_owned_documents(
    service,
    ssm_client,
):
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "DocumentIdentifiers": [
                {
                    "Name": "MyDocument",
                    "Owner": "123456789012",
                }
            ]
        }
    ]

    ssm_client.get_paginator.return_value = paginator

    result = service.list_self_owned_documents()

    assert result == [
        {
            "Name": "MyDocument",
            "Owner": "123456789012",
        }
    ]

    paginator.paginate.assert_called_once_with(
        Filters=[
            {
                "Key": "Owner",
                "Values": ["Self"],
            }
        ]
    )


def test_describe_document_permission(
    service,
    ssm_client,
):
    ssm_client.describe_document_permission.return_value = {
        "AccountIds": ["All"],
    }

    result = service.describe_document_permission(
        "MyDocument"
    )

    assert result == {
        "AccountIds": ["All"],
    }

    ssm_client.describe_document_permission.assert_called_once_with(
        Name="MyDocument",
        PermissionType="Share",
    )


def test_get_service_setting(
    service,
    ssm_client,
):
    ssm_client.get_service_setting.return_value = {
        "ServiceSetting": {
            "SettingId": "setting",
            "SettingValue": "Disable",
        }
    }

    result = service.get_service_setting(
        "setting"
    )

    assert result == {
        "ServiceSetting": {
            "SettingId": "setting",
            "SettingValue": "Disable",
        }
    }


def test_api_error_is_wrapped(
    service,
    ssm_client,
):
    from botocore.exceptions import ClientError

    ssm_client.get_service_setting.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access denied",
                }
            },
            "GetServiceSetting",
        )
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException",
    ):
        service.get_service_setting(
            "setting"
        )
