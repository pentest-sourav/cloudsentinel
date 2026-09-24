from engine.rules.registry.stepfunctions_handlers import (
    STEPFUNCTIONS_DATA_SOURCE_HANDLERS,
    collect_stepfunctions_activities,
    collect_stepfunctions_state_machines,
)


def test_stepfunctions_handlers_are_registered():
    assert (
        "stepfunctions_state_machines"
        in STEPFUNCTIONS_DATA_SOURCE_HANDLERS
    )
    assert (
        "stepfunctions_activities"
        in STEPFUNCTIONS_DATA_SOURCE_HANDLERS
    )

    assert (
        STEPFUNCTIONS_DATA_SOURCE_HANDLERS[
            "stepfunctions_state_machines"
        ]
        is collect_stepfunctions_state_machines
    )

    assert (
        STEPFUNCTIONS_DATA_SOURCE_HANDLERS[
            "stepfunctions_activities"
        ]
        is collect_stepfunctions_activities
    )
