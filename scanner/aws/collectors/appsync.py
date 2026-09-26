from typing import Any

from scanner.aws.services.appsync import AppSyncService


class AppSyncDataCollector:
    """
    Normalize AWS AppSync GraphQL API configuration for
    CloudSentinel security rules.

    AWS API responses are collected once and cached for the
    lifetime of the collector.
    """

    def __init__(self, service: AppSyncService):
        self.service = service

        self._apis_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_apis(self) -> list[dict[str, Any]]:
        if self._apis_cache is None:
            self._apis_cache = (
                self.service.list_graphql_apis()
            )

        return self._apis_cache

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> dict[str, str]:
        if not isinstance(tags, dict):
            return {}

        normalized: dict[str, str] = {}

        for key, value in tags.items():
            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            normalized[key] = (
                value
                if isinstance(value, str)
                else str(value)
            )

        return normalized

    @staticmethod
    def _normalize_auth_providers(
        providers: Any,
    ) -> list[str]:
        if not isinstance(providers, list):
            return []

        normalized: list[str] = []

        for provider in providers:
            if not isinstance(provider, dict):
                continue

            auth_type = provider.get(
                "authenticationType"
            )

            if isinstance(auth_type, str) and auth_type:
                normalized.append(auth_type)

        return normalized

    def collect_graphql_apis(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for api in self._get_apis():
            api_id = api.get("apiId")

            if (
                not isinstance(api_id, str)
                or not api_id
            ):
                continue

            log_config = api.get("logConfig")

            if not isinstance(log_config, dict):
                log_config = {}

            authentication_type = api.get(
                "authenticationType"
            )

            if not isinstance(authentication_type, str):
                authentication_type = None

            additional_authentication_types = (
                self._normalize_auth_providers(
                    api.get(
                        "additionalAuthenticationProviders"
                    )
                )
            )

            field_log_level = log_config.get(
                "fieldLogLevel"
            )

            if not isinstance(field_log_level, str):
                field_log_level = None

            tags = self._normalize_tags(
                api.get("tags")
            )

            normalized.append(
                {
                    "resource_id": api_id,
                    "resource_type": (
                        "appsync_graphql_api"
                    ),
                    "resource_arn": api.get("arn"),
                    "name": api.get("name"),
                    "api_type": api.get("apiType"),
                    "authentication_type": (
                        authentication_type
                    ),
                    "additional_authentication_types": (
                        additional_authentication_types
                    ),
                    "field_log_level": field_log_level,
                    "tags": tags,
                    "has_non_system_tags": bool(tags),
                }
            )

        return normalized
