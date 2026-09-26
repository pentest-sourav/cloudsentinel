from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class CodeBuildService:
    """
    Read-only AWS CodeBuild discovery service.

    Retrieves:
    - CodeBuild project configuration
    - CodeBuild report-group configuration

    This service never mutates AWS resources.
    """

    def __init__(self, session):
        self.client = create_aws_client(
            session,
            "codebuild",
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
                f"CodeBuild {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during CodeBuild "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during CodeBuild "
            f"{operation}: {exc}"
        ) from exc

    def list_project_names(self) -> list[str]:
        try:
            names: list[str] = []
            next_token: str | None = None

            while True:
                kwargs: dict[str, Any] = {
                    "sortOrder": "ASCENDING",
                    "sortBy": "NAME",
                    "maxResults": 100,
                }

                if next_token:
                    kwargs["nextToken"] = next_token

                response = self.client.list_projects(
                    **kwargs
                )

                entries = response.get(
                    "projects",
                    [],
                )

                if isinstance(entries, list):
                    names.extend(
                        name
                        for name in entries
                        if isinstance(name, str)
                    )

                next_token = response.get(
                    "nextToken"
                )

                if not isinstance(
                    next_token,
                    str,
                ) or not next_token:
                    break

            return names

        except Exception as exc:
            self._raise_api_error(
                "project discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def batch_get_projects(
        self,
        names: list[str],
    ) -> list[dict[str, Any]]:
        if not names:
            return []

        try:
            projects: list[dict[str, Any]] = []

            for start in range(
                0,
                len(names),
                100,
            ):
                batch = names[start:start + 100]

                response = self.client.batch_get_projects(
                    names=batch,
                )

                entries = response.get(
                    "projects",
                    [],
                )

                if isinstance(entries, list):
                    projects.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return projects

        except Exception as exc:
            self._raise_api_error(
                "project configuration discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_projects(
        self,
    ) -> list[dict[str, Any]]:
        names = self.list_project_names()

        return self.batch_get_projects(
            names
        )

    def list_report_group_arns(
        self,
    ) -> list[str]:
        try:
            arns: list[str] = []
            next_token: str | None = None

            while True:
                kwargs: dict[str, Any] = {
                    "sortOrder": "ASCENDING",
                    "sortBy": "NAME",
                    "maxResults": 100,
                }

                if next_token:
                    kwargs["nextToken"] = next_token

                response = self.client.list_report_groups(
                    **kwargs
                )

                entries = response.get(
                    "reportGroups",
                    [],
                )

                if isinstance(entries, list):
                    arns.extend(
                        arn
                        for arn in entries
                        if isinstance(arn, str)
                    )

                next_token = response.get(
                    "nextToken"
                )

                if not isinstance(
                    next_token,
                    str,
                ) or not next_token:
                    break

            return arns

        except Exception as exc:
            self._raise_api_error(
                "report-group discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def batch_get_report_groups(
        self,
        arns: list[str],
    ) -> list[dict[str, Any]]:
        if not arns:
            return []

        try:
            report_groups: list[dict[str, Any]] = []

            for start in range(
                0,
                len(arns),
                100,
            ):
                batch = arns[start:start + 100]

                response = self.client.batch_get_report_groups(
                    reportGroupArns=batch,
                )

                entries = response.get(
                    "reportGroups",
                    [],
                )

                if isinstance(entries, list):
                    report_groups.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

            return report_groups

        except Exception as exc:
            self._raise_api_error(
                "report-group configuration discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_report_groups(
        self,
    ) -> list[dict[str, Any]]:
        arns = self.list_report_group_arns()

        return self.batch_get_report_groups(
            arns
        )
