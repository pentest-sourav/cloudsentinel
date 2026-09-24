from typing import Any

from scanner.aws.services.stepfunctions import StepFunctionsService


class StepFunctionsDataCollector:
    """
    Normalize AWS Step Functions data for CloudSentinel rules.

    State machine logging and activity tagging are exposed through
    separate data sources because they represent different AWS
    resource types.
    """

    def __init__(self, service: StepFunctionsService):
        self.service = service

        self._state_machines_cache: list[
            dict[str, Any]
        ] | None = None

        self._state_machine_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._activities_cache: list[
            dict[str, Any]
        ] | None = None

        self._activity_tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    def _get_state_machines(self) -> list[dict[str, Any]]:
        if self._state_machines_cache is None:
            self._state_machines_cache = (
                self.service.list_state_machines()
            )

        return self._state_machines_cache

    def _get_state_machine_details(
        self,
        state_machine_arn: str,
    ) -> dict[str, Any]:
        if state_machine_arn not in self._state_machine_details_cache:
            self._state_machine_details_cache[
                state_machine_arn
            ] = self.service.describe_state_machine(
                state_machine_arn
            )

        return self._state_machine_details_cache[
            state_machine_arn
        ]

    def _get_activities(self) -> list[dict[str, Any]]:
        if self._activities_cache is None:
            self._activities_cache = (
                self.service.list_activities()
            )

        return self._activities_cache

    def _get_activity_tags(
        self,
        activity_arn: str,
    ) -> list[dict[str, Any]]:
        if activity_arn not in self._activity_tags_cache:
            self._activity_tags_cache[
                activity_arn
            ] = self.service.list_activity_tags(
                activity_arn
            )

        return self._activity_tags_cache[activity_arn]

    def collect_state_machines(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for state_machine in self._get_state_machines():
            state_machine_arn = state_machine.get(
                "stateMachineArn"
            )

            if not isinstance(state_machine_arn, str):
                continue

            if not state_machine_arn:
                continue

            details = self._get_state_machine_details(
                state_machine_arn
            )

            normalized.append(
                {
                    "state_machine_arn": state_machine_arn,
                    "name": details.get("name")
                    or state_machine.get("name"),
                    "type": details.get("type")
                    or state_machine.get("type"),
                    "status": details.get("status"),
                    "logging_configuration": (
                        details.get("logging_configuration")
                        or {}
                    ),
                    "tracing_configuration": (
                        details.get("tracing_configuration")
                        or {}
                    ),
                    "encryption_configuration": (
                        details.get("encryption_configuration")
                        or {}
                    ),
                }
            )

        return normalized

    def collect_activities(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for activity in self._get_activities():
            activity_arn = activity.get("activityArn")

            if not isinstance(activity_arn, str):
                continue

            if not activity_arn:
                continue

            normalized.append(
                {
                    "activity_arn": activity_arn,
                    "name": activity.get("name"),
                    "tags": self._get_activity_tags(
                        activity_arn
                    ),
                }
            )

        return normalized
