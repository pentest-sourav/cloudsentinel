from engine.rules.aws.s3.acl import (
    build_s3_acl_finding,
    check_s3_acl,
)
from engine.rules.aws.s3.encryption import (
    build_s3_encryption_finding,
    check_s3_encryption,
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
from engine.rules.aws.s3.policy import (
    build_s3_bucket_policy_finding,
    check_s3_bucket_policy,
)
from engine.rules.aws.s3.public_access import (
    build_s3_public_access_finding,
    check_s3_public_access,
)
from engine.rules.aws.s3.versioning import (
    build_s3_versioning_finding,
    check_s3_versioning,
)


S3_RULES = [
    {
        "rule_id": "CS-AWS-S3-001",
        "name": "public_access",
        "service_method": "get_public_access_block",
        "configuration_argument": "public_access_block",
        "check": check_s3_public_access,
        "build_finding": build_s3_public_access_finding,
    },
    {
        "rule_id": "CS-AWS-S3-002",
        "name": "encryption",
        "service_method": "get_bucket_encryption",
        "configuration_argument": "encryption_configuration",
        "check": check_s3_encryption,
        "build_finding": build_s3_encryption_finding,
    },
    {
        "rule_id": "CS-AWS-S3-003",
        "name": "policy",
        "service_method": "get_bucket_policy_status",
        "configuration_argument": "policy_status",
        "check": check_s3_bucket_policy,
        "build_finding": build_s3_bucket_policy_finding,
    },
    {
        "rule_id": "CS-AWS-S3-004",
        "name": "acl",
        "service_method": "get_bucket_acl",
        "configuration_argument": "acl",
        "check": check_s3_acl,
        "build_finding": build_s3_acl_finding,
    },
    {
        "rule_id": "CS-AWS-S3-005",
        "name": "versioning",
        "service_method": "get_bucket_versioning",
        "configuration_argument": "versioning_status",
        "check": check_s3_versioning,
        "build_finding": build_s3_versioning_finding,
    },
    {
        "rule_id": "CS-AWS-S3-006",
        "name": "logging",
        "service_method": "get_bucket_logging",
        "configuration_argument": "logging_configuration",
        "check": check_s3_logging,
        "build_finding": build_s3_logging_finding,
    },
    {
        "rule_id": "CS-AWS-S3-007",
        "name": "object_lock",
        "service_method": "get_object_lock_configuration",
        "configuration_argument": "object_lock_configuration",
        "check": check_s3_object_lock,
        "build_finding": build_s3_object_lock_finding,
    },
    {
        "rule_id": "CS-AWS-S3-008",
        "name": "ownership",
        "service_method": "get_bucket_ownership_controls",
        "configuration_argument": "ownership_configuration",
        "check": check_s3_ownership,
        "build_finding": build_s3_ownership_finding,
    },
]
