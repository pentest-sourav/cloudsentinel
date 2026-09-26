from typing import Any

from scanner.aws.services.appflow import AppFlowService


class AppFlowDataCollector:
    """
    Normalize Amazon AppFlow flows for CloudSentinel.

    The collector performs no security evaluation.
    AWS system tags using the aws: prefix are ignored when
    determining organizational tag presence.
    """

    def __init__(self, service: AppFlowService):
        self.service = service
        self._flows_cache: list[dict[str, Any]] | None = None

    @staticmethod
    def _normalize_tags(
        tags: dict[str, str],
    ) -> dict[str, str]:
        if not isinstance(tags, dict):
            return {}

        return {
            str(key): str(value)
            for key, value in tags.items()
            if isinstance(key, str)
            and not key.lower().startswith("aws:")
        }

    def collect_flows(self) -> list[dict[str, Any]]:
        if self._flows_cache is not None:
            return self._flows_cache

        normalized: list[dict[str, Any]] = []

        for flow in self.service.list_flows():
            if not isinstance(flow, dict):
                continue

            flow_name = flow.get("flowName")
            flow_arn = flow.get("flowArn")

            if not flow_name or not flow_arn:
                continue

            tags = self._normalize_tags(
                self.service.list_tags_for_resource(
                    flow_arn
                )
            )

            normalized.append(
                {
                    "flow_name": flow_name,
                    "flow_arn": flow_arn,
                    "flow_status": flow.get("flowStatus"),
                    "source_connector_type": flow.get(
                        "sourceConnectorType"
                    ),
                    "destination_connector_type": flow.get(
                        "destinationConnectorType"
                    ),
                    "tags": tags,
                    "tag_data_available": True,
                    "has_non_system_tags": bool(tags),
                }
            )

        self._flows_cache = normalized
        return self._flows_cache
