import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class StepFunctionsService:
    """
    Read-only AWS Step Functions discovery service.

    This service retrieves state machine logging configuration and
    activity tags. Security evaluation is handled separately by
    CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.stepfunctions_client = create_aws_client(
            session,
            "stepfunctions",
        )

    def list_state_machines(self) -> list[dict[str, Any]]:
        try:
            paginator = self.stepfunctions_client.get_paginator(
                "list_state_machines"
            )

            state_machines: list[dict[str, Any]] = []

            for page in paginator.paginate():
                machines = page.get("stateMachines", [])

                if isinstance(machines, list):
                    state_machines.extend(
                        machine
                        for machine in machines
                        if isinstance(machine, dict)
                    )

            return state_machines

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "Step Functions state machine discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Step Functions state machine "
                f"discovery: {exc}"
            ) from exc

    def describe_state_machine(
        self,
        state_machine_arn: str,
    ) -> dict[str, Any]:
        try:
            response = self.stepfunctions_client.describe_state_machine(
                stateMachineArn=state_machine_arn,
                includedData="METADATA_ONLY",
            )

            return {
                "state_machine_arn": response.get(
                    "stateMachineArn"
                ),
                "name": response.get("name"),
                "type": response.get("type"),
                "status": response.get("status"),
                "logging_configuration": (
                    response.get("loggingConfiguration") or {}
                ),
                "tracing_configuration": (
                    response.get("tracingConfiguration") or {}
                ),
                "encryption_configuration": (
                    response.get("encryptionConfiguration") or {}
                ),
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "Step Functions state machine description failed for "
                f"'{state_machine_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error while describing Step Functions "
                f"state machine '{state_machine_arn}': {exc}"
            ) from exc

    def list_activities(self) -> list[dict[str, Any]]:
        try:
            paginator = self.stepfunctions_client.get_paginator(
                "list_activities"
            )

            activities: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_activities = page.get("activities", [])

                if isinstance(page_activities, list):
                    activities.extend(
                        activity
                        for activity in page_activities
                        if isinstance(activity, dict)
                    )

            return activities

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "Step Functions activity discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Step Functions activity "
                f"discovery: {exc}"
            ) from exc

    def list_activity_tags(
        self,
        activity_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.stepfunctions_client.list_tags_for_resource(
                resourceArn=activity_arn,
            )

            tags = response.get("tags", [])

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "Step Functions activity tag discovery failed for "
                f"'{activity_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error while retrieving Step Functions "
                f"activity tags for '{activity_arn}': {exc}"
            ) from exc
