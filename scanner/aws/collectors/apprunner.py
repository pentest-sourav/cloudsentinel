from typing import Any

from scanner.aws.services.apprunner import AppRunnerService


class AppRunnerDataCollector:
    """
    Normalize AWS App Runner services and VPC connectors.

    The collector performs no security evaluation.
    It converts AWS responses into stable contracts consumed
    by the App Runner rules.
    """

    def __init__(self, service: AppRunnerService):
        self.service = service
        self._services_cache: list[dict[str, Any]] | None = None
        self._connectors_cache: list[dict[str, Any]] | None = None

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> tuple[dict[str, str], bool]:
        """
        Return non-system tags and whether tag data was available.

        AWS system tags beginning with aws: are ignored because
        Security Hub App Runner tagging controls ignore them.
        """
        if not isinstance(tags, list):
            return {}, False

        normalized: dict[str, str] = {}

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")
            value = tag.get("Value", "")

            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            normalized[key] = str(value)

        return normalized, True

    def _get_services(self) -> list[dict[str, Any]]:
        if self._services_cache is None:
            self._services_cache = self.service.list_services()

        return self._services_cache

    def _get_connectors(self) -> list[dict[str, Any]]:
        if self._connectors_cache is None:
            self._connectors_cache = (
                self.service.list_vpc_connectors()
            )

        return self._connectors_cache

    def _collect_service(
        self,
        service: dict[str, Any],
    ) -> dict[str, Any] | None:
        service_arn = service.get("ServiceArn")
        service_name = service.get("ServiceName")
        service_id = service.get("ServiceId")
        status = service.get("Status")

        if (
            not isinstance(service_arn, str)
            or not service_arn
        ):
            return None

        if (
            not isinstance(service_name, str)
            or not service_name
        ):
            service_name = service_id

        if (
            not isinstance(service_name, str)
            or not service_name
        ):
            return None

        raw_tags = self.service.list_tags_for_resource(
            service_arn
        )

        tags, tag_data_available = self._normalize_tags(
            raw_tags
        )

        return {
            "service_id": service_id,
            "service_arn": service_arn,
            "service_name": service_name,
            "status": status,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

    def collect_services(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for service in self._get_services():
            if not isinstance(service, dict):
                continue

            collected = self._collect_service(service)

            if collected is not None:
                normalized.append(collected)

        return normalized

    def _collect_connector(
        self,
        connector: dict[str, Any],
    ) -> dict[str, Any] | None:
        connector_arn = connector.get("VpcConnectorArn")
        connector_name = connector.get("VpcConnectorName")
        revision = connector.get("VpcConnectorRevision")
        status = connector.get("Status")

        if (
            not isinstance(connector_arn, str)
            or not connector_arn
        ):
            return None

        if (
            not isinstance(connector_name, str)
            or not connector_name
        ):
            return None

        raw_tags = self.service.list_tags_for_resource(
            connector_arn
        )

        tags, tag_data_available = self._normalize_tags(
            raw_tags
        )

        return {
            "vpc_connector_arn": connector_arn,
            "vpc_connector_name": connector_name,
            "vpc_connector_revision": revision,
            "status": status,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

    def collect_vpc_connectors(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for connector in self._get_connectors():
            if not isinstance(connector, dict):
                continue

            collected = self._collect_connector(connector)

            if collected is not None:
                normalized.append(collected)

        return normalized
