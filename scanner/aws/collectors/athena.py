from typing import Any

from scanner.aws.services.athena import AthenaService


class AthenaDataCollector:
    """Normalize AWS Athena data for CloudSentinel rules."""

    def __init__(
        self,
        service: AthenaService,
    ):
        self.service = service

        self._catalogs_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._workgroups_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._workgroup_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._tags_cache: dict[
            str,
            list[dict[str, str]],
        ] = {}

    def _get_catalogs(self) -> list[dict[str, Any]]:
        if self._catalogs_cache is None:
            self._catalogs_cache = (
                self.service.list_data_catalogs()
            )

        return self._catalogs_cache

    def _get_workgroups(self) -> list[dict[str, Any]]:
        if self._workgroups_cache is None:
            self._workgroups_cache = (
                self.service.list_workgroups()
            )

        return self._workgroups_cache

    def _get_workgroup_details(
        self,
        name: str,
    ) -> dict[str, Any]:
        if name not in self._workgroup_details_cache:
            self._workgroup_details_cache[name] = (
                self.service.get_workgroup(name)
            )

        return self._workgroup_details_cache[name]

    def _get_tags(
        self,
        resource_arn: str,
    ) -> list[dict[str, str]]:
        if resource_arn not in self._tags_cache:
            self._tags_cache[resource_arn] = (
                self.service.list_tags_for_resource(
                    resource_arn
                )
            )

        return self._tags_cache[resource_arn]

    @staticmethod
    def _normalize_tags(
        tags: list[dict[str, str]],
    ) -> dict[str, str]:
        normalized: dict[str, str] = {}

        for tag in tags:
            key = tag.get("Key")
            value = tag.get("Value", "")

            if (
                isinstance(key, str)
                and key
                and not key.startswith("aws:")
            ):
                normalized[key] = str(value)

        return normalized

    def collect_data_catalogs(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for catalog in self._get_catalogs():
            name = catalog.get("CatalogName")

            if (
                not isinstance(name, str)
                or not name
            ):
                continue

            arn = self.service.build_resource_arn(
                "datacatalog",
                name,
            )

            tags = (
                self._normalize_tags(
                    self._get_tags(arn)
                )
                if arn
                else None
            )

            normalized.append(
                {
                    "catalog_name": name,
                    "catalog_arn": arn,
                    "tags": tags,
                    "tag_data_available": tags is not None,
                    "has_non_system_tags": bool(tags),
                }
            )

        return normalized

    def collect_workgroups(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for summary in self._get_workgroups():
            name = summary.get("Name")

            if (
                not isinstance(name, str)
                or not name
            ):
                continue

            details = self._get_workgroup_details(
                name
            )

            configuration = details.get(
                "Configuration",
                {},
            )

            if not isinstance(configuration, dict):
                configuration = {}

            arn = self.service.build_resource_arn(
                "workgroup",
                name,
            )

            tags = (
                self._normalize_tags(
                    self._get_tags(arn)
                )
                if arn
                else None
            )

            publish_metrics = configuration.get(
                "PublishCloudWatchMetricsEnabled"
            )

            if not isinstance(
                publish_metrics,
                bool,
            ):
                publish_metrics = None

            normalized.append(
                {
                    "workgroup_name": name,
                    "workgroup_arn": arn,
                    "tags": tags,
                    "tag_data_available": tags is not None,
                    "has_non_system_tags": bool(tags),
                    "publish_cloudwatch_metrics_enabled": (
                        publish_metrics
                    ),
                }
            )

        return normalized
