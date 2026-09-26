from __future__ import annotations

from typing import Any

from scanner.aws.services.detective import DetectiveService


class DetectiveDataCollector:
    """Normalizes Amazon Detective behavior graph data."""

    def __init__(self, service: DetectiveService):
        self.service = service
        self._graphs_cache: list[dict[str, Any]] | None = None
        self._tags_cache: dict[str, dict[str, str]] = {}

    def _get_graphs(self) -> list[dict[str, Any]]:
        if self._graphs_cache is None:
            self._graphs_cache = self.service.list_graphs()

        return self._graphs_cache

    def _get_tags(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        if resource_arn not in self._tags_cache:
            self._tags_cache[resource_arn] = (
                self.service.list_tags_for_resource(
                    resource_arn
                )
            )

        return self._tags_cache[resource_arn]

    @staticmethod
    def _non_system_tags(
        tags: dict[str, str],
    ) -> dict[str, str]:
        if not isinstance(tags, dict):
            return {}

        return {
            key: value
            for key, value in tags.items()
            if not key.lower().startswith("aws:")
        }

    def collect_graphs(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []

        for graph in self._get_graphs():
            resource_arn = graph.get("Arn")

            if not isinstance(resource_arn, str) or not resource_arn:
                continue

            tags = self._non_system_tags(
                self._get_tags(resource_arn)
            )

            result.append(
                {
                    "resource_name": resource_arn.rsplit(
                        ":",
                        1,
                    )[-1],
                    "resource_arn": resource_arn,
                    "resource_type": "AWS::Detective::Graph",
                    "created_time": graph.get("CreatedTime"),
                    "tags": tags,
                    "tag_data_available": True,
                    "has_non_system_tags": bool(tags),
                }
            )

        return result
