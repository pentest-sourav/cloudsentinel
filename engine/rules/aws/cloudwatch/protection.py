from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CloudWatchAlarmActionsResult:
    resource_id: str
    alarm_arn: str | None
    alarm_actions: list[Any]
    state_value: str | None


@dataclass(frozen=True)
class CloudWatchAlarmEnabledResult:
    resource_id: str
    alarm_arn: str | None
    actions_enabled: bool | None
    state_value: str | None


@dataclass(frozen=True)
class CloudWatchLogRetentionResult:
    resource_id: str
    retention_in_days: int | None
    minimum_retention_days: int


def check_cloudwatch_alarm_actions(
    resource_id: str,
    alarm_arn: str | None,
    alarm_actions: list[Any],
    state_value: str | None,
) -> CloudWatchAlarmActionsResult | None:
    if not resource_id:
        return None

    if not isinstance(alarm_actions, list):
        alarm_actions = []

    if alarm_actions:
        return None

    return CloudWatchAlarmActionsResult(
        resource_id=resource_id,
        alarm_arn=alarm_arn,
        alarm_actions=alarm_actions,
        state_value=state_value,
    )


def check_cloudwatch_alarm_actions_enabled(
    resource_id: str,
    alarm_arn: str | None,
    actions_enabled: bool | None,
    state_value: str | None,
) -> CloudWatchAlarmEnabledResult | None:
    if not resource_id:
        return None

    if actions_enabled is True:
        return None

    return CloudWatchAlarmEnabledResult(
        resource_id=resource_id,
        alarm_arn=alarm_arn,
        actions_enabled=actions_enabled,
        state_value=state_value,
    )


def check_cloudwatch_log_retention(
    resource_id: str,
    retention_in_days: int | None,
    minimum_retention_days: int = 365,
) -> CloudWatchLogRetentionResult | None:
    if not resource_id:
        return None

    if isinstance(retention_in_days, bool):
        retention_in_days = None

    if (
        isinstance(retention_in_days, int)
        and retention_in_days >= minimum_retention_days
    ):
        return None

    return CloudWatchLogRetentionResult(
        resource_id=resource_id,
        retention_in_days=retention_in_days,
        minimum_retention_days=minimum_retention_days,
    )
