from typing import Any

from scanner.aws.services.appconfig import AppConfigService


class AppConfigDataCollector:
    """
    Normalize AWS AppConfig resources for CloudSentinel.

    Supported resource types:
    - applications
    - configuration profiles
    - environments
    - extension associations

    The collector performs no security evaluation.
    """

    def __init__(self, service: AppConfigService):
        self.service = service

        self._applications_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._configuration_profiles_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._environments_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._extension_associations_cache: (
            list[dict[str, Any]] | None
        ) = None

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> tuple[dict[str, str], bool]:
        """
        Return non-system tags and whether tag data was available.

        AWS system tags beginning with aws: are ignored because
        AWS Resource Tagging controls do not count them.
        """
        if not isinstance(tags, dict):
            return {}, False

        normalized: dict[str, str] = {}

        for key, value in tags.items():
            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            normalized[key] = str(value)

        return normalized, True

    def _get_applications(self) -> list[dict[str, Any]]:
        if self._applications_cache is None:
            self._applications_cache = (
                self.service.list_applications()
            )

        return self._applications_cache

    def _get_configuration_profiles(
        self,
    ) -> list[dict[str, Any]]:
        if self._configuration_profiles_cache is None:
            profiles: list[dict[str, Any]] = []

            for application in self._get_applications():
                application_id = application.get("Id")

                if (
                    not isinstance(application_id, str)
                    or not application_id
                ):
                    continue

                for profile in (
                    self.service.list_configuration_profiles(
                        application_id
                    )
                ):
                    if not isinstance(profile, dict):
                        continue

                    profile_copy = dict(profile)
                    profile_copy["_application_id"] = (
                        application_id
                    )
                    profiles.append(profile_copy)

            self._configuration_profiles_cache = profiles

        return self._configuration_profiles_cache

    def _get_environments(
        self,
    ) -> list[dict[str, Any]]:
        if self._environments_cache is None:
            environments: list[dict[str, Any]] = []

            for application in self._get_applications():
                application_id = application.get("Id")

                if (
                    not isinstance(application_id, str)
                    or not application_id
                ):
                    continue

                for environment in (
                    self.service.list_environments(
                        application_id
                    )
                ):
                    if not isinstance(environment, dict):
                        continue

                    environment_copy = dict(environment)
                    environment_copy["_application_id"] = (
                        application_id
                    )
                    environments.append(environment_copy)

            self._environments_cache = environments

        return self._environments_cache

    def _get_extension_associations(
        self,
    ) -> list[dict[str, Any]]:
        if self._extension_associations_cache is None:
            self._extension_associations_cache = (
                self.service.list_extension_associations()
            )

        return self._extension_associations_cache

    def _collect_tagged_resource(
        self,
        *,
        resource_name: str,
        resource_arn: str | None,
        resource_type: str,
    ) -> dict[str, Any] | None:
        if (
            not isinstance(resource_name, str)
            or not resource_name
            or not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return None

        raw_tags = self.service.list_tags_for_resource(
            resource_arn
        )

        tags, tag_data_available = self._normalize_tags(
            raw_tags
        )

        return {
            "resource_name": resource_name,
            "resource_arn": resource_arn,
            "resource_type": resource_type,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

    def collect_applications(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for application in self._get_applications():
            if not isinstance(application, dict):
                continue

            application_id = application.get("Id")
            application_name = application.get("Name")

            if (
                not isinstance(application_id, str)
                or not application_id
            ):
                continue

            if (
                not isinstance(application_name, str)
                or not application_name
            ):
                application_name = application_id

            collected = self._collect_tagged_resource(
                resource_name=application_name,
                resource_arn=self.service.application_arn(
                    application_id
                ),
                resource_type="appconfig_application",
            )

            if collected is not None:
                collected["application_id"] = application_id
                normalized.append(collected)

        return normalized

    def collect_configuration_profiles(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for profile in self._get_configuration_profiles():
            application_id = profile.get(
                "_application_id"
            )
            profile_id = profile.get("Id")
            profile_name = profile.get("Name")

            if (
                not isinstance(application_id, str)
                or not application_id
                or not isinstance(profile_id, str)
                or not profile_id
            ):
                continue

            if (
                not isinstance(profile_name, str)
                or not profile_name
            ):
                profile_name = profile_id

            collected = self._collect_tagged_resource(
                resource_name=profile_name,
                resource_arn=(
                    self.service.configuration_profile_arn(
                        application_id,
                        profile_id,
                    )
                ),
                resource_type=(
                    "appconfig_configuration_profile"
                ),
            )

            if collected is not None:
                collected["application_id"] = application_id
                collected["configuration_profile_id"] = (
                    profile_id
                )
                normalized.append(collected)

        return normalized

    def collect_environments(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for environment in self._get_environments():
            application_id = environment.get(
                "_application_id"
            )
            environment_id = environment.get("Id")
            environment_name = environment.get("Name")

            if (
                not isinstance(application_id, str)
                or not application_id
                or not isinstance(environment_id, str)
                or not environment_id
            ):
                continue

            if (
                not isinstance(environment_name, str)
                or not environment_name
            ):
                environment_name = environment_id

            collected = self._collect_tagged_resource(
                resource_name=environment_name,
                resource_arn=self.service.environment_arn(
                    application_id,
                    environment_id,
                ),
                resource_type="appconfig_environment",
            )

            if collected is not None:
                collected["application_id"] = application_id
                collected["environment_id"] = environment_id
                normalized.append(collected)

        return normalized

    def collect_extension_associations(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for association in self._get_extension_associations():
            association_id = association.get("Id")

            if (
                not isinstance(association_id, str)
                or not association_id
            ):
                continue

            collected = self._collect_tagged_resource(
                resource_name=association_id,
                resource_arn=(
                    self.service.extension_association_arn(
                        association_id
                    )
                ),
                resource_type=(
                    "appconfig_extension_association"
                ),
            )

            if collected is not None:
                collected["association_id"] = association_id
                collected["extension_arn"] = (
                    association.get("ExtensionArn")
                )
                collected["associated_resource_arn"] = (
                    association.get("ResourceArn")
                )
                normalized.append(collected)

        return normalized
