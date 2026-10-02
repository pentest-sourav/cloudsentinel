from __future__ import annotations

from typing import Any

from scanner.aws.services.securityhub import (
    SecurityHubService,
)


class SecurityHubDataCollector:
    """Normalize AWS Security Hub posture for CloudSentinel rules."""

    def __init__(
        self,
        service: SecurityHubService,
    ):
        self.service = service

        self._hub_cache: dict[str, Any] | None = None
        self._hub_loaded = False

        self._standards_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_hub(
        self,
    ) -> dict[str, Any] | None:
        if not self._hub_loaded:
            self._hub_cache = self.service.describe_hub()
            self._hub_loaded = True

        return self._hub_cache

    def _get_standards(
        self,
    ) -> list[dict[str, Any]]:
        if self._standards_cache is None:
            self._standards_cache = (
                self.service.get_enabled_standards()
            )

        return self._standards_cache

    def collect_hub(
        self,
    ) -> dict[str, Any]:
        hub = self._get_hub()

        if hub is None:
            return {
                "resource_id": "securityhub",
                "enabled": False,
                "hub_arn": None,
                "subscribed_at": None,
                "auto_enable_controls": None,
                "control_finding_generator": None,
            }

        return {
            "resource_id": hub.get(
                "HubArn",
                "securityhub",
            ),
            "enabled": True,
            "hub_arn": hub.get("HubArn"),
            "subscribed_at": hub.get(
                "SubscribedAt"
            ),
            "auto_enable_controls": hub.get(
                "AutoEnableControls"
            ),
            "control_finding_generator": hub.get(
                "ControlFindingGenerator"
            ),
        }

    def collect_standards(
        self,
    ) -> list[dict[str, Any]]:
        return [
            {
                "resource_id": (
                    item.get(
                        "StandardsSubscriptionArn"
                    )
                    or item.get("StandardsArn")
                    or "securityhub-standard"
                ),
                "standards_subscription_arn": item.get(
                    "StandardsSubscriptionArn"
                ),
                "standards_arn": item.get(
                    "StandardsArn"
                ),
                "standards_status": item.get(
                    "StandardsStatus"
                ),
                "standards_controls_updatable": (
                    item.get(
                        "StandardsControlsUpdatable"
                    )
                ),
                "standards_status_reason": (
                    (
                        item.get(
                            "StandardsStatusReason"
                        )
                        or {}
                    ).get("StatusReasonCode")
                ),
                "provider": item.get("Provider"),
                "standards_input": item.get(
                    "StandardsInput",
                    {},
                ),
            }
            for item in self._get_standards()
        ]
