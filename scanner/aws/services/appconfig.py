from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class AppConfigService:
    """
    Read-only AWS AppConfig discovery service.

    The service layer is responsible only for AWS API access
    and stable AWS resource ARN construction. Security
    evaluation remains in CloudSentinel rules.
    """

    def __init__(
        self,
        session,
        account_id: str | None = None,
        region_name: str | None = None,
    ):
        self.session = session
        self.account_id = account_id
        self.region_name = (
            region_name
            or getattr(session, "region_name", None)
        )

        self.appconfig_client = create_aws_client(
            session,
            "appconfig",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AppConfig {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AppConfig "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AppConfig "
            f"{operation}: {exc}"
        ) from exc

    def _build_arn(
        self,
        resource_path: str,
    ) -> str | None:
        if (
            not isinstance(self.account_id, str)
            or not self.account_id
            or not isinstance(self.region_name, str)
            or not self.region_name
            or not isinstance(resource_path, str)
            or not resource_path
        ):
            return None

        return (
            f"arn:aws:appconfig:{self.region_name}:"
            f"{self.account_id}:{resource_path}"
        )

    def application_arn(
        self,
        application_id: str,
    ) -> str | None:
        if (
            not isinstance(application_id, str)
            or not application_id
        ):
            return None

        return self._build_arn(
            f"application/{application_id}"
        )

    def configuration_profile_arn(
        self,
        application_id: str,
        configuration_profile_id: str,
    ) -> str | None:
        if (
            not isinstance(application_id, str)
            or not application_id
            or not isinstance(configuration_profile_id, str)
            or not configuration_profile_id
        ):
            return None

        return self._build_arn(
            "application/"
            f"{application_id}/configurationprofile/"
            f"{configuration_profile_id}"
        )

    def environment_arn(
        self,
        application_id: str,
        environment_id: str,
    ) -> str | None:
        if (
            not isinstance(application_id, str)
            or not application_id
            or not isinstance(environment_id, str)
            or not environment_id
        ):
            return None

        return self._build_arn(
            f"application/{application_id}/environment/"
            f"{environment_id}"
        )

    def extension_association_arn(
        self,
        association_id: str,
    ) -> str | None:
        if (
            not isinstance(association_id, str)
            or not association_id
        ):
            return None

        return self._build_arn(
            f"extensionassociation/{association_id}"
        )

    def list_applications(self) -> list[dict[str, Any]]:
        """
        Discover all AppConfig applications in the current region.
        """
        try:
            paginator = self.appconfig_client.get_paginator(
                "list_applications"
            )

            applications: list[dict[str, Any]] = []

            for page in paginator.paginate():
                items = page.get("Items", [])

                if isinstance(items, list):
                    applications.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return applications

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "application discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_configuration_profiles(
        self,
        application_id: str,
    ) -> list[dict[str, Any]]:
        """
        Discover all configuration profiles for an application.
        """
        if (
            not isinstance(application_id, str)
            or not application_id
        ):
            return []

        try:
            paginator = self.appconfig_client.get_paginator(
                "list_configuration_profiles"
            )

            profiles: list[dict[str, Any]] = []

            for page in paginator.paginate(
                ApplicationId=application_id,
            ):
                items = page.get("Items", [])

                if isinstance(items, list):
                    profiles.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return profiles

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"configuration profile discovery "
                f"for application {application_id}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_environments(
        self,
        application_id: str,
    ) -> list[dict[str, Any]]:
        """
        Discover all environments for an application.
        """
        if (
            not isinstance(application_id, str)
            or not application_id
        ):
            return []

        try:
            paginator = self.appconfig_client.get_paginator(
                "list_environments"
            )

            environments: list[dict[str, Any]] = []

            for page in paginator.paginate(
                ApplicationId=application_id,
            ):
                items = page.get("Items", [])

                if isinstance(items, list):
                    environments.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return environments

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"environment discovery "
                f"for application {application_id}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_extension_associations(
        self,
    ) -> list[dict[str, Any]]:
        """
        Discover all AppConfig extension associations in
        the current region.
        """
        try:
            paginator = self.appconfig_client.get_paginator(
                "list_extension_associations"
            )

            associations: list[dict[str, Any]] = []

            for page in paginator.paginate():
                items = page.get("Items", [])

                if isinstance(items, list):
                    associations.extend(
                        item
                        for item in items
                        if isinstance(item, dict)
                    )

            return associations

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "extension association discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags_for_resource(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        """
        Return tags for an AppConfig resource ARN.
        """
        if (
            not isinstance(resource_arn, str)
            or not resource_arn
        ):
            return {}

        try:
            response = self.appconfig_client.list_tags_for_resource(
                ResourceArn=resource_arn,
            )

            tags = response.get("Tags", {})

            if not isinstance(tags, dict):
                return {}

            return {
                str(key): str(value)
                for key, value in tags.items()
                if isinstance(key, str)
            }

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"tag discovery for {resource_arn}",
                exc,
            )
            raise AssertionError("unreachable")
