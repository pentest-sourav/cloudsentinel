from typing import Any

from scanner.aws.services.macie import MacieService


class MacieDataCollector:
    def __init__(self, service: MacieService):
        self.service = service
        self._account_cache: list[dict[str, Any]] | None = None

    def collect_account_configuration(self) -> list[dict[str, Any]]:
        if self._account_cache is not None:
            return self._account_cache

        session = self.service.get_macie_session()

        account_id = session.get("accountId")
        resource_id = account_id or "aws-account"

        administrator = self.service.get_administrator_account()

        administrator_account_id = None
        relationship_status = None
        is_member_account = False

        if administrator is not None:
            administrator_data = administrator.get("administrator") or {}

            administrator_account_id = administrator_data.get(
                "accountId"
            )
            relationship_status = administrator_data.get(
                "relationshipStatus"
            )
            is_member_account = True

        automated_discovery_status = None
        auto_enable_organization_members = None
        classification_scope_id = None
        sensitivity_inspection_template_id = None

        if not is_member_account:
            configuration = (
                self.service.get_automated_discovery_configuration()
            )

            if configuration:
                automated_discovery_status = configuration.get(
                    "status"
                )
                auto_enable_organization_members = configuration.get(
                    "autoEnableOrganizationMembers"
                )
                classification_scope_id = configuration.get(
                    "classificationScopeId"
                )
                sensitivity_inspection_template_id = configuration.get(
                    "sensitivityInspectionTemplateId"
                )

        self._account_cache = [
            {
                "resource_id": resource_id,
                "account_id": account_id,
                "macie_status": session.get("status"),
                "administrator_account_id": administrator_account_id,
                "relationship_status": relationship_status,
                "is_member_account": is_member_account,
                "automated_discovery_status": (
                    automated_discovery_status
                ),
                "auto_enable_organization_members": (
                    auto_enable_organization_members
                ),
                "classification_scope_id": classification_scope_id,
                "sensitivity_inspection_template_id": (
                    sensitivity_inspection_template_id
                ),
            }
        ]

        return self._account_cache

    def collect_account(self) -> list[dict[str, Any]]:
        return self.collect_account_configuration()
