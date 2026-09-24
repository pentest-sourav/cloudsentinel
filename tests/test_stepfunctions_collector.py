from unittest.mock import Mock

from scanner.aws.collectors.stepfunctions import (
    StepFunctionsDataCollector,
)


STATE_MACHINE_ARN = (
    "arn:aws:states:region:account:"
    "stateMachine:test-machine"
)

ACTIVITY_ARN = (
    "arn:aws:states:region:account:"
    "activity:test-activity"
)


def test_collect_state_machines_normalizes_security_data():
    service = Mock()

    service.list_state_machines.return_value = [
        {
            "stateMachineArn": STATE_MACHINE_ARN,
            "name": "test-machine",
            "type": "STANDARD",
        }
    ]

    service.describe_state_machine.return_value = {
        "state_machine_arn": STATE_MACHINE_ARN,
        "name": "test-machine",
        "type": "STANDARD",
        "status": "ACTIVE",
        "logging_configuration": {
            "level": "ERROR",
        },
        "tracing_configuration": {
            "enabled": True,
        },
        "encryption_configuration": {},
    }

    collector = StepFunctionsDataCollector(service)

    result = collector.collect_state_machines()

    assert result == [
        {
            "state_machine_arn": STATE_MACHINE_ARN,
            "name": "test-machine",
            "type": "STANDARD",
            "status": "ACTIVE",
            "logging_configuration": {
                "level": "ERROR",
            },
            "tracing_configuration": {
                "enabled": True,
            },
            "encryption_configuration": {},
        }
    ]


def test_collect_activities_normalizes_tags():
    service = Mock()

    service.list_activities.return_value = [
        {
            "activityArn": ACTIVITY_ARN,
            "name": "test-activity",
        }
    ]

    service.list_activity_tags.return_value = [
        {
            "key": "Environment",
            "value": "prod",
        }
    ]

    collector = StepFunctionsDataCollector(service)

    result = collector.collect_activities()

    assert result == [
        {
            "activity_arn": ACTIVITY_ARN,
            "name": "test-activity",
            "tags": [
                {
                    "key": "Environment",
                    "value": "prod",
                }
            ],
        }
    ]


def test_collector_caches_state_machine_data():
    service = Mock()

    service.list_state_machines.return_value = [
        {
            "stateMachineArn": STATE_MACHINE_ARN,
        }
    ]

    service.describe_state_machine.return_value = {
        "state_machine_arn": STATE_MACHINE_ARN,
        "name": "test-machine",
        "type": "STANDARD",
        "status": "ACTIVE",
        "logging_configuration": {},
    }

    collector = StepFunctionsDataCollector(service)

    collector.collect_state_machines()
    collector.collect_state_machines()

    service.list_state_machines.assert_called_once()
    service.describe_state_machine.assert_called_once_with(
        STATE_MACHINE_ARN
    )


def test_collector_caches_activity_data():
    service = Mock()

    service.list_activities.return_value = [
        {
            "activityArn": ACTIVITY_ARN,
        }
    ]

    service.list_activity_tags.return_value = []

    collector = StepFunctionsDataCollector(service)

    collector.collect_activities()
    collector.collect_activities()

    service.list_activities.assert_called_once()
    service.list_activity_tags.assert_called_once_with(
        ACTIVITY_ARN
    )
