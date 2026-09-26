from unittest.mock import Mock

from scanner.aws.collectors.cloudformation import (
    CloudFormationDataCollector,
)


def make_service():
    return Mock()


def test_collect_stacks_normalizes_security_relevant_fields():
    service = make_service()

    service.describe_stacks.return_value = [
        {
            "StackName": "prod",
            "StackId": "arn:aws:cloudformation:ap-south-1:123:stack/prod/id",
            "StackStatus": "CREATE_COMPLETE",
            "RoleARN": "arn:aws:iam::123:role/cfn",
            "EnableTerminationProtection": True,
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
                {
                    "Key": "aws:createdBy",
                    "Value": "system",
                },
            ],
        }
    ]

    result = CloudFormationDataCollector(
        service
    ).collect_stacks()

    assert result == [
        {
            "stack_id": (
                "arn:aws:cloudformation:ap-south-1:123:"
                "stack/prod/id"
            ),
            "stack_name": "prod",
            "stack_status": "CREATE_COMPLETE",
            "role_arn": "arn:aws:iam::123:role/cfn",
            "termination_protection_enabled": True,
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_stacks_skips_delete_complete_stacks():
    service = make_service()

    service.describe_stacks.return_value = [
        {
            "StackName": "deleted",
            "StackId": "arn:deleted",
            "StackStatus": "DELETE_COMPLETE",
        },
        {
            "StackName": "active",
            "StackId": "arn:active",
            "StackStatus": "UPDATE_COMPLETE",
            "RoleARN": "arn:role",
            "EnableTerminationProtection": False,
            "Tags": [],
        },
    ]

    result = CloudFormationDataCollector(
        service
    ).collect_stacks()

    assert len(result) == 1
    assert result[0]["stack_name"] == "active"


def test_collect_stacks_handles_missing_optional_fields():
    service = make_service()

    service.describe_stacks.return_value = [
        {
            "StackName": "untagged",
            "StackId": "arn:untagged",
            "StackStatus": "CREATE_COMPLETE",
        }
    ]

    result = CloudFormationDataCollector(
        service
    ).collect_stacks()

    assert result == [
        {
            "stack_id": "arn:untagged",
            "stack_name": "untagged",
            "stack_status": "CREATE_COMPLETE",
            "role_arn": None,
            "termination_protection_enabled": None,
            "tags": {},
            "tag_data_available": False,
            "has_non_system_tags": False,
        }
    ]


def test_collect_stacks_caches_service_call():
    service = make_service()

    service.describe_stacks.return_value = []

    collector = CloudFormationDataCollector(service)

    assert collector.collect_stacks() == []
    assert collector.collect_stacks() == []

    service.describe_stacks.assert_called_once()
