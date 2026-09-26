from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.cloudformation import (
    CloudFormationService,
)


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"

    client = Mock()

    service = CloudFormationService(session)
    service.cloudformation_client = client

    return service, client


def test_describe_stacks_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Stacks": [
                {
                    "StackName": "one",
                    "StackId": "arn:stack:one",
                }
            ]
        },
        {
            "Stacks": [
                {
                    "StackName": "two",
                    "StackId": "arn:stack:two",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.describe_stacks() == [
        {
            "StackName": "one",
            "StackId": "arn:stack:one",
        },
        {
            "StackName": "two",
            "StackId": "arn:stack:two",
        },
    ]

    client.get_paginator.assert_called_once_with(
        "describe_stacks"
    )


def test_describe_stacks_ignores_non_dict_entries():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Stacks": [
                {"StackName": "valid"},
                None,
                "invalid",
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    assert service.describe_stacks() == [
        {"StackName": "valid"}
    ]


def test_describe_stacks_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "DescribeStacks",
    )

    client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.describe_stacks()
