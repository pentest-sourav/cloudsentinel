from typing import Any, Callable

from scanner.aws.collectors.stepfunctions import (
    StepFunctionsDataCollector,
)


def collect_stepfunctions_state_machines(
    collector: StepFunctionsDataCollector,
) -> list[dict]:
    return collector.collect_state_machines()


def collect_stepfunctions_activities(
    collector: StepFunctionsDataCollector,
) -> list[dict]:
    return collector.collect_activities()


STEPFUNCTIONS_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[StepFunctionsDataCollector], Any],
] = {
    "stepfunctions_state_machines": (
        collect_stepfunctions_state_machines
    ),
    "stepfunctions_activities": (
        collect_stepfunctions_activities
    ),
}
