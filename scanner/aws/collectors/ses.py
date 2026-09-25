from typing import Any

from scanner.aws.services.ses import SESService


class SESDataCollector:
    """
    Normalize Amazon SES configuration for
    CloudSentinel security rules.
    """

    def __init__(self, service: SESService):
        self.service = service

        self._contact_lists_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._contact_list_metadata_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._configuration_sets_cache: (
            list[str] | None
        ) = None

        self._configuration_set_metadata_cache: dict[
            str,
            dict[str, Any],
        ] = {}

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
            value = tag.get(
                "Value",
                "",
            )

            if (
                not isinstance(key, str)
                or not key
            ):
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
            if not tag["Key"]
            .lower()
            .startswith("aws:")
        ]

    def _get_contact_lists(
        self,
    ) -> list[dict[str, Any]]:
        if self._contact_lists_cache is None:
            self._contact_lists_cache = (
                self.service.list_contact_lists()
            )

        return self._contact_lists_cache

    def _get_contact_list_metadata(
        self,
        name: str,
    ) -> dict[str, Any]:
        if name not in self._contact_list_metadata_cache:
            self._contact_list_metadata_cache[name] = (
                self.service.get_contact_list(name)
            )

        return self._contact_list_metadata_cache[name]

    def _get_configuration_sets(
        self,
    ) -> list[str]:
        if self._configuration_sets_cache is None:
            self._configuration_sets_cache = (
                self.service.list_configuration_sets()
            )

        return self._configuration_sets_cache

    def _get_configuration_set_metadata(
        self,
        name: str,
    ) -> dict[str, Any]:
        if name not in self._configuration_set_metadata_cache:
            self._configuration_set_metadata_cache[name] = (
                self.service.get_configuration_set(name)
            )

        return (
            self._configuration_set_metadata_cache[name]
        )

    def collect_contact_lists(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for entry in self._get_contact_lists():
            name = entry.get(
                "ContactListName"
            )

            if (
                not isinstance(name, str)
                or not name
            ):
                continue

            metadata = self._get_contact_list_metadata(
                name
            )

            tags = self._normalize_tags(
                metadata.get("Tags")
            )

            normalized.append(
                {
                    "resource_id": name,
                    "resource_type": "ses_contact_list",
                    "tags": self._non_system_tags(tags),
                }
            )

        return normalized

    def collect_configuration_sets(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for name in self._get_configuration_sets():
            metadata = (
                self._get_configuration_set_metadata(name)
            )

            tags = self._normalize_tags(
                metadata.get("Tags")
            )

            delivery_options = metadata.get(
                "DeliveryOptions",
                {},
            )

            if not isinstance(
                delivery_options,
                dict,
            ):
                delivery_options = {}

            tls_policy = delivery_options.get(
                "TlsPolicy"
            )

            normalized.append(
                {
                    "resource_id": name,
                    "resource_type": (
                        "ses_configuration_set"
                    ),
                    "tags": self._non_system_tags(tags),
                    "tls_policy": tls_policy,
                }
            )

        return normalized
