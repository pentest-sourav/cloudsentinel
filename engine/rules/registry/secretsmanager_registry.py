from engine.rules.aws.secretsmanager.automatic_rotation import (
    build_secretsmanager_automatic_rotation_finding,
    check_secretsmanager_automatic_rotation,
)
from engine.rules.aws.secretsmanager.rotation_period import (
    build_secretsmanager_rotation_period_finding,
    check_secretsmanager_rotation_period,
)
from engine.rules.aws.secretsmanager.tagging import (
    build_secretsmanager_tagging_finding,
    check_secretsmanager_tagging,
)
from engine.rules.aws.secretsmanager.unused_secret import (
    build_secretsmanager_unused_secret_finding,
    check_secretsmanager_unused_secret,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


SECRETSMANAGER_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SECRETSMANAGER-001",
            name=(
                "Secrets Manager secrets should have "
                "automatic rotation enabled"
            ),
            data_source="secretsmanager_secrets",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "rotation_enabled",
                "rotation_rules",
            ],
            check=(
                check_secretsmanager_automatic_rotation
            ),
            build_finding=(
                build_secretsmanager_automatic_rotation_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-SECRETSMANAGER-003",
            name=(
                "Remove unused Secrets Manager secrets"
            ),
            data_source="secretsmanager_secrets",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "last_accessed_date",
            ],
            check=check_secretsmanager_unused_secret,
            build_finding=(
                build_secretsmanager_unused_secret_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-SECRETSMANAGER-004",
            name=(
                "Secrets Manager secrets should be "
                "rotated within a specified number "
                "of days"
            ),
            data_source="secretsmanager_secrets",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "last_rotated_date",
            ],
            check=check_secretsmanager_rotation_period,
            build_finding=(
                build_secretsmanager_rotation_period_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-SECRETSMANAGER-005",
            name=(
                "Secrets Manager secrets should be tagged"
            ),
            data_source="secretsmanager_secrets",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "tags",
            ],
            check=check_secretsmanager_tagging,
            build_finding=(
                build_secretsmanager_tagging_finding
            ),
        ),
    ]
)
