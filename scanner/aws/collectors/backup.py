from typing import Any

from scanner.aws.services.backup import BackupService


class BackupDataCollector:
    """
    Normalize AWS Backup data for CloudSentinel rules.

    All AWS API data is cached for the duration of one scan.
    """

    def __init__(
        self,
        service: BackupService,
    ):
        self.service = service

        self._vaults_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._plans_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._report_plans_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._recovery_points_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._plan_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._plan_selections_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._vault_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> list[dict[str, str]]:
        if not isinstance(tags, dict):
            return []

        normalized: list[dict[str, str]] = []

        for key, value in tags.items():
            if not isinstance(key, str):
                continue

            if key.lower().startswith("aws:"):
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

    def _get_vaults(self) -> list[dict[str, Any]]:
        if self._vaults_cache is None:
            self._vaults_cache = (
                self.service.list_backup_vaults()
            )

        return self._vaults_cache

    def _get_plans(self) -> list[dict[str, Any]]:
        if self._plans_cache is None:
            self._plans_cache = (
                self.service.list_backup_plans()
            )

        return self._plans_cache

    def _get_report_plans(self) -> list[dict[str, Any]]:
        if self._report_plans_cache is None:
            self._report_plans_cache = (
                self.service.list_report_plans()
            )

        return self._report_plans_cache

    def _get_recovery_points(
        self,
        vault_name: str,
    ) -> list[dict[str, Any]]:
        if vault_name not in self._recovery_points_cache:
            self._recovery_points_cache[vault_name] = (
                self.service.list_recovery_points(
                    vault_name
                )
            )

        return self._recovery_points_cache[vault_name]

    def _get_plan_details(
        self,
        plan_id: str,
    ) -> dict[str, Any]:
        if plan_id not in self._plan_details_cache:
            self._plan_details_cache[plan_id] = (
                self.service.get_backup_plan(
                    plan_id
                )
            )

        return self._plan_details_cache[plan_id]

    def _get_plan_selections(
        self,
        plan_id: str,
    ) -> list[dict[str, Any]]:
        if plan_id not in self._plan_selections_cache:
            self._plan_selections_cache[plan_id] = (
                self.service.list_backup_selections(
                    plan_id
                )
            )

        return self._plan_selections_cache[plan_id]

    def _get_vault_details(
        self,
        vault_name: str,
    ) -> dict[str, Any]:
        if vault_name not in self._vault_details_cache:
            self._vault_details_cache[vault_name] = (
                self.service.describe_backup_vault(
                    vault_name
                )
            )

        return self._vault_details_cache[vault_name]

    def collect_vaults(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for vault in self._get_vaults():
            name = vault.get("BackupVaultName")
            arn = vault.get("BackupVaultArn")

            if not isinstance(name, str) or not name:
                continue

            if not isinstance(arn, str) or not arn:
                continue

            details = self._get_vault_details(name)

            normalized.append(
                {
                    "resource_id": name,
                    "resource_type": "backup_vault",
                    "resource_arn": arn,
                    "vault_state": details.get(
                        "VaultState",
                        vault.get("VaultState"),
                    ),
                    "vault_type": details.get(
                        "VaultType",
                        vault.get("VaultType"),
                    ),
                    "locked": details.get("Locked"),
                    "lock_date": details.get("LockDate"),
                    "min_retention_days": details.get(
                        "MinRetentionDays"
                    ),
                    "max_retention_days": details.get(
                        "MaxRetentionDays"
                    ),
                    "encryption_key_arn": details.get(
                        "EncryptionKeyArn"
                    ),
                    "encryption_key_type": details.get(
                        "EncryptionKeyType"
                    ),
                    "number_of_recovery_points": details.get(
                        "NumberOfRecoveryPoints"
                    ),
                }
            )

        return normalized

    def collect_recovery_points(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for vault in self._get_vaults():
            vault_name = vault.get("BackupVaultName")

            if (
                not isinstance(vault_name, str)
                or not vault_name
            ):
                continue

            for point in self._get_recovery_points(
                vault_name
            ):
                arn = point.get("RecoveryPointArn")

                if not isinstance(arn, str) or not arn:
                    continue

                normalized.append(
                    {
                        "resource_id": arn,
                        "resource_type": (
                            "backup_recovery_point"
                        ),
                        "resource_arn": arn,
                        "backup_vault_name": vault_name,
                        "encryption_key_arn": point.get(
                            "EncryptionKeyArn"
                        ),
                        "encryption_key_type": point.get(
                            "EncryptionKeyType"
                        ),
                        "status": point.get("Status"),
                        "resource_arn_source": point.get(
                            "ResourceArn"
                        ),
                        "resource_type_source": point.get(
                            "ResourceType"
                        ),
                    }
                )

        return normalized

    def collect_backup_plans(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for plan in self._get_plans():
            arn = plan.get("BackupPlanArn")
            plan_id = plan.get("BackupPlanId")

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(plan_id, str) or not plan_id:
                continue

            details = self._get_plan_details(plan_id)

            backup_plan = details.get(
                "BackupPlan",
                {},
            )

            if not isinstance(backup_plan, dict):
                backup_plan = {}

            rules = backup_plan.get(
                "Rules",
                [],
            )

            if not isinstance(rules, list):
                rules = []

            selections = self._get_plan_selections(
                plan_id
            )

            normalized.append(
                {
                    "resource_id": plan_id,
                    "resource_type": "backup_plan",
                    "resource_arn": arn,
                    "plan_name": backup_plan.get(
                        "BackupPlanName",
                        plan.get("BackupPlanName"),
                    ),
                    "rules": [
                        rule
                        for rule in rules
                        if isinstance(rule, dict)
                    ],
                    "rules_count": len(
                        [
                            rule
                            for rule in rules
                            if isinstance(rule, dict)
                        ]
                    ),
                    "selection_count": len(selections),
                    "selections": selections,
                    "version_id": details.get(
                        "VersionId",
                        plan.get("VersionId"),
                    ),
                }
            )

        return normalized

    def collect_report_plans(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for plan in self._get_report_plans():
            arn = plan.get("ReportPlanArn")
            name = plan.get("ReportPlanName")

            if not isinstance(arn, str) or not arn:
                continue

            resource_id = (
                name
                if isinstance(name, str) and name
                else arn
            )

            normalized.append(
                {
                    "resource_id": resource_id,
                    "resource_type": "backup_report_plan",
                    "resource_arn": arn,
                }
            )

        return normalized
