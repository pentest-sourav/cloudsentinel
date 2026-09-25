from typing import Any

from scanner.aws.services.route53 import Route53Service


class Route53DataCollector:
    """
    Normalize Amazon Route 53 configuration for
    CloudSentinel security rules.
    """

    def __init__(self, service: Route53Service):
        self.service = service

        self._health_checks_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._hosted_zones_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._query_logging_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._health_check_tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    def _get_health_checks(
        self,
    ) -> list[dict[str, Any]]:
        if self._health_checks_cache is None:
            self._health_checks_cache = (
                self.service.list_health_checks()
            )

        return self._health_checks_cache

    def _get_hosted_zones(
        self,
    ) -> list[dict[str, Any]]:
        if self._hosted_zones_cache is None:
            self._hosted_zones_cache = (
                self.service.list_hosted_zones()
            )

        return self._hosted_zones_cache

    def _get_query_logging_configs(
        self,
    ) -> list[dict[str, Any]]:
        if self._query_logging_cache is None:
            self._query_logging_cache = (
                self.service.list_query_logging_configs()
            )

        return self._query_logging_cache

    def _get_health_check_tags(
        self,
        health_check_id: str,
    ) -> list[dict[str, Any]]:
        if health_check_id not in self._health_check_tags_cache:
            self._health_check_tags_cache[health_check_id] = (
                self.service.list_tags_for_resource(
                    "healthcheck",
                    health_check_id,
                )
            )

        return self._health_check_tags_cache[
            health_check_id
        ]

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> list[dict[str, str]]:
        if not isinstance(tags, list):
            return []

        normalized: list[dict[str, str]] = []

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")
            value = tag.get("Value", "")

            if not isinstance(key, str) or not key:
                continue

            normalized.append(
                {
                    "Key": key,
                    "Value": (
                        value
                        if isinstance(value, str)
                        else str(value)
                    ),
                }
            )

        return normalized

    @staticmethod
    def _non_system_tags(
        tags: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        return [
            tag
            for tag in tags
            if not tag["Key"].lower().startswith("aws:")
        ]

    @staticmethod
    def _normalize_hosted_zone_id(
        hosted_zone_id: Any,
    ) -> str | None:
        if not isinstance(hosted_zone_id, str):
            return None

        if not hosted_zone_id:
            return None

        return hosted_zone_id.removeprefix(
            "/hostedzone/"
        )

    def collect_health_checks(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for health_check in self._get_health_checks():
            health_check_id = health_check.get("Id")

            if (
                not isinstance(health_check_id, str)
                or not health_check_id
            ):
                continue

            tags = self._normalize_tags(
                self._get_health_check_tags(
                    health_check_id
                )
            )

            normalized.append(
                {
                    "resource_id": health_check_id,
                    "resource_type": "route53_health_check",
                    "tags": self._non_system_tags(tags),
                }
            )

        return normalized

    def collect_hosted_zones(
        self,
    ) -> list[dict[str, Any]]:
        query_logging_configs = (
            self._get_query_logging_configs()
        )

        logged_zone_ids = {
            self._normalize_hosted_zone_id(
                config.get("HostedZoneId")
            )
            for config in query_logging_configs
            if isinstance(config, dict)
        }

        logged_zone_ids.discard(None)

        normalized: list[dict[str, Any]] = []

        for hosted_zone in self._get_hosted_zones():
            hosted_zone_id = (
                self._normalize_hosted_zone_id(
                    hosted_zone.get("Id")
                )
            )

            if not hosted_zone_id:
                continue

            config = hosted_zone.get(
                "Config",
                {},
            )

            if not isinstance(config, dict):
                config = {}

            private_zone = config.get(
                "PrivateZone"
            )

            if private_zone is True:
                continue

            normalized.append(
                {
                    "resource_id": hosted_zone_id,
                    "resource_type": "route53_hosted_zone",
                    "name": hosted_zone.get("Name"),
                    "private_zone": False,
                    "query_logging_enabled": (
                        hosted_zone_id
                        in logged_zone_ids
                    ),
                }
            )

        return normalized
