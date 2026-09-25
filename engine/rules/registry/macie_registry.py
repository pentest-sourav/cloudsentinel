from engine.rules.aws.macie.protection import (
    build_macie_001,
    build_macie_002,
    check_automated_sensitive_data_discovery,
    check_macie_enabled,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


MACIE_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-MACIE-001",
            name=(
                "Amazon Macie should be enabled"
            ),
            data_source="macie_account",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "macie_status",
            ],
            check=check_macie_enabled,
            build_finding=build_macie_001,
        ),
        RuleDefinition(
            rule_id="CS-AWS-MACIE-002",
            name=(
                "Amazon Macie automated sensitive "
                "data discovery should be enabled"
            ),
            data_source="macie_account",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "macie_status",
                "is_member_account",
                "automated_discovery_status",
            ],
            check=(
                check_automated_sensitive_data_discovery
            ),
            build_finding=build_macie_002,
        ),
    ]
)
