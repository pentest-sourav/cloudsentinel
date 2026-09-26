from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.athena import AthenaService


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"
    session.get_partition_for_region.return_value = "aws"

    client = Mock()

    service = AthenaService(
        session,
        account_id="123456789012",
        region_name="ap-south-1",
    )

    service.athena_client = client

    return service, client


def test_list_data_catalogs_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "DataCatalogsSummary": [
                {"CatalogName": "one"},
            ],
        },
        {
            "DataCatalogsSummary": [
                {"CatalogName": "two"},
            ],
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_data_catalogs() == [
        {"CatalogName": "one"},
        {"CatalogName": "two"},
    ]

    client.get_paginator.assert_called_once_with(
        "list_data_catalogs"
    )


def test_list_workgroups_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "WorkGroups": [
                {"Name": "one"},
            ],
        },
        {
            "WorkGroups": [
                {"Name": "two"},
            ],
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_workgroups() == [
        {"Name": "one"},
        {"Name": "two"},
    ]


def test_get_workgroup_returns_workgroup_details():
    service, client = make_service()

    client.get_work_group.return_value = {
        "WorkGroup": {
            "Name": "primary",
            "Configuration": {
                "PublishCloudWatchMetricsEnabled": True,
            },
        },
    }

    assert (
        service.get_workgroup("primary")["Name"]
        == "primary"
    )

    client.get_work_group.assert_called_once_with(
        WorkGroup="primary"
    )


def test_list_tags_for_resource_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
        {
            "Tags": [
                {
                    "Key": "Owner",
                    "Value": "security",
                },
            ],
        },
    ]

    client.get_paginator.return_value = paginator

    result = service.list_tags_for_resource(
        "arn:aws:athena:test"
    )

    assert result == [
        {
            "Key": "Environment",
            "Value": "prod",
        },
        {
            "Key": "Owner",
            "Value": "security",
        },
    ]

    paginator.paginate.assert_called_once_with(
        ResourceARN="arn:aws:athena:test"
    )


def test_build_resource_arn_uses_athena_resource_format():
    service, _ = make_service()

    assert service.build_resource_arn(
        "datacatalog",
        "AwsDataCatalog",
    ) == (
        "arn:aws:athena:ap-south-1:123456789012:"
        "datacatalog/AwsDataCatalog"
    )


def test_aws_client_error_is_normalized():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            },
        },
        "ListWorkGroups",
    )

    client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_workgroups()
