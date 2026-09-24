from unittest.mock import Mock

from scanner.aws.services.stepfunctions import (
    StepFunctionsService,
)


STATE_MACHINE_ARN = (
    "arn:aws:states:region:account:"
    "stateMachine:test-machine"
)

ACTIVITY_ARN = (
    "arn:aws:states:region:account:"
    "activity:test-activity"
)


def test_list_state_machines_collects_all_pages():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    paginator = Mock()
    client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "stateMachines": [
                {
                    "stateMachineArn": STATE_MACHINE_ARN,
                    "name": "test-machine",
                }
            ]
        },
        {
            "stateMachines": [
                {
                    "stateMachineArn": (
                        "arn:aws:states:region:account:"
                        "stateMachine:second"
                    )
                }
            ]
        },
    ]

    service = StepFunctionsService(session)

    result = service.list_state_machines()

    assert len(result) == 2
    assert result[0]["stateMachineArn"] == STATE_MACHINE_ARN


def test_describe_state_machine_returns_logging_configuration():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.describe_state_machine.return_value = {
        "stateMachineArn": STATE_MACHINE_ARN,
        "name": "test-machine",
        "type": "STANDARD",
        "status": "ACTIVE",
        "loggingConfiguration": {
            "level": "ALL",
            "includeExecutionData": True,
        },
    }

    service = StepFunctionsService(session)

    result = service.describe_state_machine(
        STATE_MACHINE_ARN
    )

    assert result["state_machine_arn"] == STATE_MACHINE_ARN
    assert result["name"] == "test-machine"
    assert result["logging_configuration"]["level"] == "ALL"

    client.describe_state_machine.assert_called_once_with(
        stateMachineArn=STATE_MACHINE_ARN,
        includedData="METADATA_ONLY",
    )


def test_list_activities_collects_all_pages():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    paginator = Mock()
    client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "activities": [
                {
                    "activityArn": ACTIVITY_ARN,
                    "name": "test-activity",
                }
            ]
        }
    ]

    service = StepFunctionsService(session)

    result = service.list_activities()

    assert result == [
        {
            "activityArn": ACTIVITY_ARN,
            "name": "test-activity",
        }
    ]


def test_list_activity_tags_returns_tags():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.list_tags_for_resource.return_value = {
        "tags": [
            {
                "key": "Environment",
                "value": "prod",
            }
        ]
    }

    service = StepFunctionsService(session)

    result = service.list_activity_tags(ACTIVITY_ARN)

    assert result == [
        {
            "key": "Environment",
            "value": "prod",
        }
    ]

    client.list_tags_for_resource.assert_called_once_with(
        resourceArn=ACTIVITY_ARN,
    )
