from __future__ import annotations

from typing import Any

from scanner.aws.services.config import ConfigService


class ConfigDataCollector:
    """Normalize AWS Config data for CloudSentinel rules."""

    def __init__(self, service: ConfigService):
        self.service = service

        self._recorders: list[dict[str, Any]] | None = None
        self._statuses: list[dict[str, Any]] | None = None

    def _get_recorders(self) -> list[dict[str, Any]]:
        if self._recorders is None:
            self._recorders = (
                self.service.describe_configuration_recorders()
            )

        return self._recorders

    def _get_statuses(self) -> list[dict[str, Any]]:
        if self._statuses is None:
            self._statuses = (
                self.service.describe_configuration_recorder_status()
            )

        return self._statuses

    @staticmethod
    def _recording_group(
        recorder: dict[str, Any],
    ) -> dict[str, Any]:
        value = recorder.get("recordingGroup")

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _recording_strategy(
        recorder: dict[str, Any],
    ) -> dict[str, Any]:
        group = ConfigDataCollector._recording_group(
            recorder
        )

        value = group.get("recordingStrategy")

        return value if isinstance(value, dict) else {}

    def collect_account(self) -> dict[str, Any]:
        """Return account-level AWS Config recording posture.

        This deliberately returns exactly one object so an account with
        zero configuration recorders can still be evaluated by a
        single-collection rule.
        """
        recorders = self.collect_recorders()
        statuses = self._get_statuses()

        recorder_names = {
            item.get("name")
            for item in recorders
            if item.get("name")
        }

        status_names = {
            item.get("name")
            for item in statuses
            if item.get("name")
        }

        active_names = {
            item.get("name")
            for item in recorders
            if item.get("name") and item.get("recording") is True
        }

        # A service-linked recorder can expose its status through the
        # status API. Include it even if the recorder description is not
        # present in the customer-managed recorder response.
        active_names.update(
            item.get("name")
            for item in statuses
            if item.get("name") and item.get("recording") is True
        )

        all_names = recorder_names | status_names

        return {
            "recorder_count": len(all_names),
            "active_recorder_count": len(active_names),
            "recorder_names": sorted(all_names),
            "active_recorder_names": sorted(active_names),
        }

    def collect_recorders(self) -> list[dict[str, Any]]:
        statuses_by_name = {
            status.get("name"): status
            for status in self._get_statuses()
            if status.get("name")
        }

        normalized: list[dict[str, Any]] = []

        for recorder in self._get_recorders():
            name = recorder.get("name")

            if not name:
                continue

            status = statuses_by_name.get(
                name,
                {},
            )

            group = self._recording_group(
                recorder
            )

            strategy = self._recording_strategy(
                recorder
            )

            normalized.append(
                {
                    "name": name,
                    "role_arn": recorder.get(
                        "roleARN"
                    ),
                    "service_principal": recorder.get(
                        "servicePrincipal"
                    ),
                    "recording": bool(
                        status.get(
                            "recording",
                            False,
                        )
                    ),
                    "last_status": status.get(
                        "lastStatus"
                    ),
                    "last_error_code": status.get(
                        "lastErrorCode"
                    ),
                    "last_error_message": status.get(
                        "lastErrorMessage"
                    ),
                    "all_supported": bool(
                        group.get(
                            "allSupported",
                            False,
                        )
                    ),
                    "include_global_resource_types": bool(
                        group.get(
                            "includeGlobalResourceTypes",
                            False,
                        )
                    ),
                    "resource_types": list(
                        group.get(
                            "resourceTypes"
                        )
                        or []
                    ),
                    "recording_strategy": strategy.get(
                        "useOnly"
                    ),
                    "recording_group": group,
                }
            )

        return normalized
