from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.s3.public_access import (
    build_s3_public_access_finding,
    check_s3_public_access,
)
from engine.rules.aws.s3.encryption import (
    build_s3_encryption_finding,
    check_s3_encryption,
)
from engine.rules.aws.s3.policy import (
    build_s3_bucket_policy_finding,
    check_s3_bucket_policy,
)
from engine.rules.aws.s3.acl import (
    build_s3_acl_finding,
    check_s3_acl,
)
from engine.rules.aws.s3.versioning import (
    build_s3_versioning_finding,
    check_s3_versioning,
)
from engine.rules.aws.s3.logging import (
    build_s3_logging_finding,
    check_s3_logging,
)
from engine.rules.aws.s3.object_lock import (
    build_s3_object_lock_finding,
    check_s3_object_lock,
)
from engine.rules.aws.s3.ownership import (
    build_s3_ownership_finding,
    check_s3_ownership,
)


S3_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-S3-001",
            name="public_access",
            data_source="s3_public_access",
            collection_mode="multiple",
            check_arguments=["bucket_name", "public_access_block"],
            check=check_s3_public_access,
            build_finding=build_s3_public_access_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-002",
            name="encryption",
            data_source="s3_encryption",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "encryption_configuration",
            ],
            check=check_s3_encryption,
            build_finding=build_s3_encryption_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-003",
            name="bucket_policy",
            data_source="s3_bucket_policy",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "policy_status",
            ],
            check=check_s3_bucket_policy,
            build_finding=build_s3_bucket_policy_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-004",
            name="acl",
            data_source="s3_acl",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "acl",
            ],
            check=check_s3_acl,
            build_finding=build_s3_acl_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-005",
            name="versioning",
            data_source="s3_versioning",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "versioning_status",
            ],
            check=check_s3_versioning,
            build_finding=build_s3_versioning_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-006",
            name="logging",
            data_source="s3_logging",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "logging_configuration",
            ],
            check=check_s3_logging,
            build_finding=build_s3_logging_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-007",
            name="object_lock",
            data_source="s3_object_lock",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "object_lock_configuration",
            ],
            check=check_s3_object_lock,
            build_finding=build_s3_object_lock_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-S3-008",
            name="ownership",
            data_source="s3_ownership",
            collection_mode="multiple",
            check_arguments=[
                "bucket_name",
                "ownership_configuration",
            ],
            check=check_s3_ownership,
            build_finding=build_s3_ownership_finding,
        ),
    ]
)
