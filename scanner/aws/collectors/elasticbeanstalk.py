from typing import Any

from scanner.aws.services.elasticbeanstalk import (
    ElasticBeanstalkService,
)


class ElasticBeanstalkDataCollector:
    """
    Normalize AWS Elastic Beanstalk configuration for security rules.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(
        self,
        service: ElasticBeanstalkService,
    ):
        self.service = service

        self._environments_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._configuration_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

    def _get_environments(self) -> list[dict[str, Any]]:
        if self._environments_cache is None:
            self._environments_cache = (
                self.service.list_environments()
            )

        return self._environments_cache

    def _get_configuration_settings(
        self,
        environment_name: str,
    ) -> list[dict[str, Any]]:
        if environment_name not in self._configuration_cache:
            self._configuration_cache[environment_name] = (
                self.service.get_configuration_settings(
                    environment_name,
                )
            )

        return self._configuration_cache[
            environment_name
        ]

    @staticmethod
    def _settings_by_option(
        configuration_settings: list[dict[str, Any]],
    ) -> dict[tuple[str, str], str]:
        values: dict[tuple[str, str], str] = {}

        for configuration in configuration_settings:
            option_settings = configuration.get(
                "OptionSettings",
                [],
            )

            if not isinstance(option_settings, list):
                continue

            for option in option_settings:
                if not isinstance(option, dict):
                    continue

                namespace = option.get("Namespace")
                option_name = option.get("OptionName")
                value = option.get("Value")

                if not isinstance(namespace, str):
                    continue

                if not isinstance(option_name, str):
                    continue

                if not isinstance(value, str):
                    continue

                values[
                    (
                        namespace,
                        option_name,
                    )
                ] = value

        return values

    def collect_environments(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for environment in self._get_environments():
            environment_name = environment.get(
                "EnvironmentName",
            )

            environment_id = environment.get(
                "EnvironmentId",
            )

            if not isinstance(environment_name, str):
                continue

            if not environment_name:
                continue

            if not isinstance(environment_id, str):
                continue

            configuration_settings = (
                self._get_configuration_settings(
                    environment_name,
                )
            )

            settings = self._settings_by_option(
                configuration_settings,
            )

            normalized.append(
                {
                    "resource_id": environment_id,
                    "resource_type": (
                        "elasticbeanstalk_environment"
                    ),
                    "resource_arn": environment.get(
                        "EnvironmentArn",
                    ),
                    "environment_name": environment_name,
                    "application_name": environment.get(
                        "ApplicationName",
                    ),
                    "status": environment.get(
                        "Status",
                    ),
                    "health": environment.get(
                        "Health",
                    ),
                    "health_status": environment.get(
                        "HealthStatus",
                    ),
                    "enhanced_health_reporting": (
                        settings.get(
                            (
                                "aws:elasticbeanstalk:"
                                "healthreporting:system",
                                "SystemType",
                            ),
                        )
                        == "enhanced"
                    ),
                    "managed_actions_enabled": (
                        settings.get(
                            (
                                "aws:elasticbeanstalk:"
                                "managedactions",
                                "ManagedActionsEnabled",
                            ),
                        )
                        == "true"
                    ),
                    "managed_update_level": settings.get(
                        (
                            "aws:elasticbeanstalk:"
                            "managedactions",
                            "UpdateLevel",
                        ),
                    ),
                    "stream_logs": (
                        settings.get(
                            (
                                "aws:elasticbeanstalk:"
                                "cloudwatch:logs",
                                "StreamLogs",
                            ),
                        )
                        == "true"
                    ),
                }
            )

        return normalized
