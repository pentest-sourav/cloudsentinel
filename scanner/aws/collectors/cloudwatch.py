from typing import Any

from scanner.aws.services.cloudwatch import CloudWatchService


class CloudWatchDataCollector:
    """
    Normalize Amazon CloudWatch configuration for
    CloudSentinel security rules.

    All AWS API data is cached for the duration of one scan.
    """

    def __init__(
        self,
        service: CloudWatchService,
    ):
        self.service = service

        self._alarms_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._log_groups_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_alarms(
        self,
    ) -> list[dict[str, Any]]:
        if self._alarms_cache is None:
            self._alarms_cache = (
                self.service.list_metric_alarms()
            )

        return self._alarms_cache

    def _get_log_groups(
        self,
    ) -> list[dict[str, Any]]:
        if self._log_groups_cache is None:
            self._log_groups_cache = (
                self.service.list_log_groups()
            )

        return self._log_groups_cache

    def collect_alarms(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for alarm in self._get_alarms():
            alarm_name = alarm.get(
                "AlarmName"
            )

            if (
                not isinstance(alarm_name, str)
                or not alarm_name
            ):
                continue

            normalized.append(
                {
                    "resource_id": alarm_name,
                    "resource_type": "cloudwatch_alarm",
                    "alarm_arn": alarm.get(
                        "AlarmArn"
                    ),
                    "alarm_name": alarm_name,
                    "actions_enabled": alarm.get(
                        "ActionsEnabled"
                    ),
                    "alarm_actions": (
                        alarm.get("AlarmActions", [])
                        if isinstance(
                            alarm.get("AlarmActions", []),
                            list,
                        )
                        else []
                    ),
                    "ok_actions": (
                        alarm.get("OKActions", [])
                        if isinstance(
                            alarm.get("OKActions", []),
                            list,
                        )
                        else []
                    ),
                    "insufficient_data_actions": (
                        alarm.get(
                            "InsufficientDataActions",
                            [],
                        )
                        if isinstance(
                            alarm.get(
                                "InsufficientDataActions",
                                [],
                            ),
                            list,
                        )
                        else []
                    ),
                    "state_value": alarm.get(
                        "StateValue"
                    ),
                    "state_reason": alarm.get(
                        "StateReason"
                    ),
                    "metric_name": alarm.get(
                        "MetricName"
                    ),
                    "namespace": alarm.get(
                        "Namespace"
                    ),
                }
            )

        return normalized

    def collect_log_groups(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for log_group in self._get_log_groups():
            name = log_group.get(
                "logGroupName"
            )

            if (
                not isinstance(name, str)
                or not name
            ):
                continue

            retention = log_group.get(
                "retentionInDays"
            )

            normalized.append(
                {
                    "resource_id": name,
                    "resource_type": "cloudwatch_log_group",
                    "log_group_name": name,
                    "retention_in_days": retention,
                    "stored_bytes": log_group.get(
                        "storedBytes"
                    ),
                    "creation_time": log_group.get(
                        "creationTime"
                    ),
                    "arn": log_group.get(
                        "arn"
                    ),
                }
            )

        return normalized
