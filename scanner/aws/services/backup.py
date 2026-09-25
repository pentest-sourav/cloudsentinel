from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class BackupService:
    """
    Read-only AWS Backup discovery service.

    Retrieves:
    - backup vaults
    - recovery points
    - backup plans
    - backup selections
    - detailed backup plan configuration
    - backup vault configuration
    """

    def __init__(self, session):
        self.backup_client = create_aws_client(
            session,
            "backup",
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
                f"AWS Backup {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during AWS Backup "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during AWS Backup "
            f"{operation}: {exc}"
        ) from exc

    def list_backup_vaults(self) -> list[dict[str, Any]]:
        vaults: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 1000,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.backup_client.list_backup_vaults(
                    **request,
                )

                entries = response.get(
                    "BackupVaultList",
                    [],
                )

                if isinstance(entries, list):
                    vaults.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return vaults

        except Exception as exc:
            self._raise_api_error(
                "ListBackupVaults",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_backup_vault(
        self,
        backup_vault_name: str,
    ) -> dict[str, Any]:
        if not backup_vault_name:
            return {}

        try:
            response = self.backup_client.describe_backup_vault(
                BackupVaultName=backup_vault_name,
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                "DescribeBackupVault",
                exc,
            )
            raise AssertionError("unreachable")

    def list_recovery_points(
        self,
        backup_vault_name: str,
    ) -> list[dict[str, Any]]:
        recovery_points: list[dict[str, Any]] = []
        next_token: str | None = None

        if not backup_vault_name:
            return recovery_points

        try:
            while True:
                request: dict[str, Any] = {
                    "BackupVaultName": backup_vault_name,
                    "MaxResults": 1000,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.backup_client
                    .list_recovery_points_by_backup_vault(
                        **request,
                    )
                )

                entries = response.get(
                    "RecoveryPoints",
                    [],
                )

                if isinstance(entries, list):
                    recovery_points.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return recovery_points

        except Exception as exc:
            self._raise_api_error(
                "ListRecoveryPointsByBackupVault",
                exc,
            )
            raise AssertionError("unreachable")

    def list_backup_plans(self) -> list[dict[str, Any]]:
        plans: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 1000,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.backup_client.list_backup_plans(
                    **request,
                )

                entries = response.get(
                    "BackupPlansList",
                    [],
                )

                if isinstance(entries, list):
                    plans.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return plans

        except Exception as exc:
            self._raise_api_error(
                "ListBackupPlans",
                exc,
            )
            raise AssertionError("unreachable")

    def get_backup_plan(
        self,
        backup_plan_id: str,
    ) -> dict[str, Any]:
        if not backup_plan_id:
            return {}

        try:
            response = self.backup_client.get_backup_plan(
                BackupPlanId=backup_plan_id,
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                "GetBackupPlan",
                exc,
            )
            raise AssertionError("unreachable")

    def list_backup_selections(
        self,
        backup_plan_id: str,
    ) -> list[dict[str, Any]]:
        selections: list[dict[str, Any]] = []
        next_token: str | None = None

        if not backup_plan_id:
            return selections

        try:
            while True:
                request: dict[str, Any] = {
                    "BackupPlanId": backup_plan_id,
                    "MaxResults": 1000,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.backup_client
                    .list_backup_selections(
                        **request,
                    )
                )

                entries = response.get(
                    "BackupSelectionsList",
                    [],
                )

                if isinstance(entries, list):
                    selections.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return selections

        except Exception as exc:
            self._raise_api_error(
                "ListBackupSelections",
                exc,
            )
            raise AssertionError("unreachable")

    def list_report_plans(self) -> list[dict[str, Any]]:
        plans: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 1000,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.backup_client.list_report_plans(
                    **request,
                )

                entries = response.get(
                    "ReportPlans",
                    [],
                )

                if isinstance(entries, list):
                    plans.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return plans

        except Exception as exc:
            self._raise_api_error(
                "ListReportPlans",
                exc,
            )
            raise AssertionError("unreachable")

    def list_tags(
        self,
        resource_arn: str,
    ) -> dict[str, str]:
        if not resource_arn:
            return {}

        try:
            response = self.backup_client.list_tags(
                ResourceArn=resource_arn,
            )

            tags = response.get(
                "Tags",
                {},
            )

            if not isinstance(tags, dict):
                return {}

            return {
                str(key): str(value)
                for key, value in tags.items()
                if isinstance(key, str)
            }

        except Exception as exc:
            self._raise_api_error(
                "ListTags",
                exc,
            )
            raise AssertionError("unreachable")
