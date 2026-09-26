from typing import Any

from scanner.aws.services.codebuild import CodeBuildService


class CodeBuildDataCollector:
    """
    Collect and normalize AWS CodeBuild security data.

    AWS API responses are cached for the duration of a scan.
    """

    def __init__(
        self,
        service: CodeBuildService,
    ):
        self.service = service

        self._projects_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._report_groups_cache: (
            list[dict[str, Any]] | None
        ) = None

    def _get_projects(
        self,
    ) -> list[dict[str, Any]]:
        if self._projects_cache is None:
            self._projects_cache = (
                self.service.list_projects()
            )

        return self._projects_cache

    def _get_report_groups(
        self,
    ) -> list[dict[str, Any]]:
        if self._report_groups_cache is None:
            self._report_groups_cache = (
                self.service.list_report_groups()
            )

        return self._report_groups_cache

    @staticmethod
    def _normalize_source(
        source: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(source, dict):
            return None

        return {
            "type": source.get("type"),
            "location": source.get("location"),
            "source_identifier": source.get(
                "sourceIdentifier"
            ),
        }

    @staticmethod
    def _normalize_environment_variable(
        variable: Any,
    ) -> dict[str, Any] | None:
        if not isinstance(variable, dict):
            return None

        name = variable.get("name")

        if not isinstance(name, str):
            return None

        return {
            "name": name,
            "type": variable.get("type"),
        }

    def collect_source_urls(
        self,
    ) -> list[dict[str, Any]]:
        """
        Normalize primary and secondary project sources.

        CodeBuild.1 is specifically concerned with
        Bitbucket repository URLs containing credentials.
        """
        normalized: list[dict[str, Any]] = []

        for project in self._get_projects():
            project_name = project.get("name")
            project_arn = project.get("arn")

            if not isinstance(
                project_name,
                str,
            ):
                continue

            sources: list[dict[str, Any]] = []

            primary = self._normalize_source(
                project.get("source")
            )

            if primary is not None:
                sources.append(primary)

            secondary = project.get(
                "secondarySources",
                [],
            )

            if isinstance(
                secondary,
                list,
            ):
                for source in secondary:
                    normalized_source = (
                        self._normalize_source(source)
                    )

                    if normalized_source is not None:
                        sources.append(
                            normalized_source
                        )

            for source in sources:
                if source.get("type") != "BITBUCKET":
                    continue

                normalized.append(
                    {
                        "resource_id": (
                            project_arn
                            if isinstance(
                                project_arn,
                                str,
                            )
                            else project_name
                        ),
                        "project_name": project_name,
                        "source_identifier": source.get(
                            "source_identifier"
                        ),
                        "source_type": source.get(
                            "type"
                        ),
                        "source_location": source.get(
                            "location"
                        ),
                    }
                )

        return normalized

    def collect_environment_credentials(
        self,
    ) -> list[dict[str, Any]]:
        """
        Normalize CodeBuild environment variables.

        Values are deliberately excluded from the normalized
        data because the control only needs the credential
        variable names and exposing values would create an
        unnecessary secret-handling risk.
        """
        normalized: list[dict[str, Any]] = []

        sensitive_names = {
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        }

        for project in self._get_projects():
            project_name = project.get("name")
            project_arn = project.get("arn")

            if not isinstance(
                project_name,
                str,
            ):
                continue

            environment = project.get(
                "environment",
                {},
            )

            if not isinstance(
                environment,
                dict,
            ):
                continue

            variables = environment.get(
                "environmentVariables",
                [],
            )

            if not isinstance(
                variables,
                list,
            ):
                continue

            for variable in variables:
                normalized_variable = (
                    self._normalize_environment_variable(
                        variable
                    )
                )

                if normalized_variable is None:
                    continue

                name = normalized_variable["name"]

                if name not in sensitive_names:
                    continue

                normalized.append(
                    {
                        "resource_id": (
                            project_arn
                            if isinstance(
                                project_arn,
                                str,
                            )
                            else project_name
                        ),
                        "project_name": project_name,
                        "variable_name": name,
                        "variable_type": (
                            normalized_variable.get(
                                "type"
                            )
                        ),
                    }
                )

        return normalized

    def collect_s3_logs(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for project in self._get_projects():
            project_name = project.get("name")
            project_arn = project.get("arn")

            if not isinstance(
                project_name,
                str,
            ):
                continue

            logs_config = project.get(
                "logsConfig",
                {},
            )

            if not isinstance(
                logs_config,
                dict,
            ):
                continue

            s3_logs = logs_config.get(
                "s3Logs",
                {},
            )

            if not isinstance(
                s3_logs,
                dict,
            ):
                continue

            normalized.append(
                {
                    "resource_id": (
                        project_arn
                        if isinstance(
                            project_arn,
                            str,
                        )
                        else project_name
                    ),
                    "project_name": project_name,
                    "status": s3_logs.get(
                        "status"
                    ),
                    "location": s3_logs.get(
                        "location"
                    ),
                    "encryption_disabled": (
                        s3_logs.get(
                            "encryptionDisabled"
                        )
                    ),
                }
            )

        return normalized

    def collect_logging_configuration(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for project in self._get_projects():
            project_name = project.get("name")
            project_arn = project.get("arn")

            if not isinstance(
                project_name,
                str,
            ):
                continue

            logs_config = project.get(
                "logsConfig",
                {},
            )

            if not isinstance(
                logs_config,
                dict,
            ):
                logs_config = {}

            cloudwatch = logs_config.get(
                "cloudWatchLogs",
                {},
            )

            s3_logs = logs_config.get(
                "s3Logs",
                {},
            )

            if not isinstance(
                cloudwatch,
                dict,
            ):
                cloudwatch = {}

            if not isinstance(
                s3_logs,
                dict,
            ):
                s3_logs = {}

            normalized.append(
                {
                    "resource_id": (
                        project_arn
                        if isinstance(
                            project_arn,
                            str,
                        )
                        else project_name
                    ),
                    "project_name": project_name,
                    "cloudwatch_status": (
                        cloudwatch.get("status")
                    ),
                    "s3_status": (
                        s3_logs.get("status")
                    ),
                }
            )

        return normalized

    def collect_report_group_exports(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for report_group in self._get_report_groups():
            arn = report_group.get("arn")
            name = report_group.get("name")

            if not isinstance(
                arn,
                str,
            ):
                continue

            export_config = report_group.get(
                "exportConfig",
                {},
            )

            if not isinstance(
                export_config,
                dict,
            ):
                export_config = {}

            export_type = export_config.get(
                "exportConfigType"
            )

            s3_destination = export_config.get(
                "s3Destination",
                {},
            )

            if not isinstance(
                s3_destination,
                dict,
            ):
                s3_destination = {}

            normalized.append(
                {
                    "resource_id": arn,
                    "report_group_name": name,
                    "export_config_type": export_type,
                    "bucket": s3_destination.get(
                        "bucket"
                    ),
                    "encryption_disabled": (
                        s3_destination.get(
                            "encryptionDisabled"
                        )
                    ),
                    "encryption_key": (
                        s3_destination.get(
                            "encryptionKey"
                        )
                    ),
                }
            )

        return normalized
