from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class ElasticBeanstalkService:
    """
    Read-only AWS Elastic Beanstalk discovery service.

    Retrieves environments and their configuration settings required
    by CloudSentinel Elastic Beanstalk security rules.
    """

    def __init__(self, session):
        self.elasticbeanstalk_client = create_aws_client(
            session,
            "elasticbeanstalk",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS Elastic Beanstalk {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Elastic Beanstalk "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Elastic Beanstalk "
            f"{operation}: {exc}"
        ) from exc

    def list_environments(self) -> list[dict[str, Any]]:
        environments: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxRecords": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.elasticbeanstalk_client.describe_environments(
                        **request,
                    )
                )

                entries = response.get(
                    "Environments",
                    [],
                )

                if isinstance(entries, list):
                    environments.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                next_value = response.get(
                    "NextToken",
                )

                if (
                    not isinstance(next_value, str)
                    or not next_value
                ):
                    break

                next_token = next_value

            return environments

        except Exception as exc:
            self._raise_api_error(
                "environment discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_configuration_settings(
        self,
        environment_name: str,
    ) -> list[dict[str, Any]]:
        if not environment_name:
            return []

        try:
            response = (
                self.elasticbeanstalk_client
                .describe_configuration_settings(
                    EnvironmentName=environment_name,
                )
            )

            configuration_settings = response.get(
                "ConfigurationSettings",
                [],
            )

            if not isinstance(
                configuration_settings,
                list,
            ):
                return []

            return [
                setting
                for setting in configuration_settings
                if isinstance(setting, dict)
            ]

        except Exception as exc:
            self._raise_api_error(
                "configuration-settings discovery",
                exc,
            )
            raise AssertionError("unreachable")
