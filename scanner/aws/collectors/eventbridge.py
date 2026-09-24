from typing import Any

from scanner.aws.services.eventbridge import EventBridgeService


class EventBridgeDataCollector:
    """
    Normalize AWS EventBridge data for CloudSentinel rules.
    """

    def __init__(self, service: EventBridgeService):
        self.service = service

        self._event_buses_cache: list[
            dict[str, Any]
        ] | None = None

        self._event_bus_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._event_bus_tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._endpoints_cache: list[
            dict[str, Any]
        ] | None = None

    def _get_event_buses(self) -> list[dict[str, Any]]:
        if self._event_buses_cache is None:
            self._event_buses_cache = (
                self.service.list_event_buses()
            )

        return self._event_buses_cache

    def _get_event_bus_details(
        self,
        event_bus_name: str,
    ) -> dict[str, Any]:
        if event_bus_name not in self._event_bus_details_cache:
            self._event_bus_details_cache[event_bus_name] = (
                self.service.describe_event_bus(event_bus_name)
            )

        return self._event_bus_details_cache[event_bus_name]

    def _get_event_bus_tags(
        self,
        event_bus_arn: str,
    ) -> list[dict[str, Any]]:
        if event_bus_arn not in self._event_bus_tags_cache:
            self._event_bus_tags_cache[event_bus_arn] = (
                self.service.list_event_bus_tags(event_bus_arn)
            )

        return self._event_bus_tags_cache[event_bus_arn]

    def _get_endpoints(self) -> list[dict[str, Any]]:
        if self._endpoints_cache is None:
            self._endpoints_cache = self.service.list_endpoints()

        return self._endpoints_cache

    def collect_event_buses(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for event_bus in self._get_event_buses():
            event_bus_name = event_bus.get("Name")

            if not isinstance(event_bus_name, str):
                continue

            if not event_bus_name:
                continue

            details = self._get_event_bus_details(
                event_bus_name
            )

            event_bus_arn = details.get("arn") or event_bus.get("Arn")

            if not isinstance(event_bus_arn, str):
                continue

            if not event_bus_arn:
                continue

            normalized.append(
                {
                    "event_bus_arn": event_bus_arn,
                    "name": details.get("name")
                    or event_bus_name,
                    "description": details.get("description"),
                    "event_source_name": (
                        details.get("event_source_name")
                        or event_bus.get("EventSourceName")
                    ),
                    "policy": details.get("policy"),
                    "tags": self._get_event_bus_tags(
                        event_bus_arn
                    ),
                }
            )

        return normalized

    def collect_endpoints(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for endpoint in self._get_endpoints():
            endpoint_arn = endpoint.get("Arn")

            if not isinstance(endpoint_arn, str):
                continue

            if not endpoint_arn:
                continue

            replication_config = endpoint.get(
                "ReplicationConfig"
            )

            if not isinstance(replication_config, dict):
                replication_config = {}

            normalized.append(
                {
                    "endpoint_arn": endpoint_arn,
                    "name": endpoint.get("Name"),
                    "state": endpoint.get("State"),
                    "replication_config": replication_config,
                    "event_buses": endpoint.get(
                        "EventBuses",
                        [],
                    ),
                }
            )

        return normalized
