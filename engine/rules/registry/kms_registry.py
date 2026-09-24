from engine.rules.aws.kms.grant_delegation import (
    build_kms_grant_delegation_finding,
    check_kms_grant_delegation,
)
from engine.rules.aws.kms.overly_permissive_policy import (
    build_kms_overly_permissive_policy_finding,
    check_kms_overly_permissive_policy,
)
from engine.rules.aws.kms.public_access import (
    build_kms_public_access_finding,
    check_kms_public_access,
)
from engine.rules.aws.kms.rotation import (
    build_kms_rotation_finding,
    check_kms_rotation,
)
from engine.rules.aws.kms.scheduled_deletion import (
    build_kms_scheduled_deletion_finding,
    check_kms_scheduled_deletion,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


KMS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-KMS-001",
            name="kms_rotation",
            data_source="kms_keys",
            collection_mode="multiple",
            check_arguments=[
                "key_id",
                "key_manager",
                "rotation_enabled",
            ],
            check=check_kms_rotation,
            build_finding=build_kms_rotation_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-KMS-002",
            name="kms_scheduled_deletion",
            data_source="kms_keys",
            collection_mode="multiple",
            check_arguments=[
                "key_id",
                "key_state",
                "deletion_date",
            ],
            check=check_kms_scheduled_deletion,
            build_finding=build_kms_scheduled_deletion_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-KMS-003",
            name="kms_public_access",
            data_source="kms_keys",
            collection_mode="multiple",
            check_arguments=[
                "key_id",
                "key_policy",
            ],
            check=check_kms_public_access,
            build_finding=build_kms_public_access_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-KMS-004",
            name="kms_overly_permissive_policy",
            data_source="kms_keys",
            collection_mode="multiple",
            check_arguments=[
                "key_id",
                "key_policy",
            ],
            check=check_kms_overly_permissive_policy,
            build_finding=build_kms_overly_permissive_policy_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-KMS-005",
            name="kms_grant_delegation",
            data_source="kms_keys",
            collection_mode="multiple",
            check_arguments=[
                "key_id",
                "grants",
            ],
            check=check_kms_grant_delegation,
            build_finding=build_kms_grant_delegation_finding,
        ),
    ]
)
