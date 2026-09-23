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
    ]
)
