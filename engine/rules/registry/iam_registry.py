from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.iam.access_key_age import (
    build_access_key_age_finding,
    check_access_key_age,
)
from engine.rules.aws.iam.root_mfa import (
    build_root_mfa_finding,
    check_root_mfa,
)
from engine.rules.aws.iam.user_mfa import (
    build_user_mfa_finding,
    check_user_mfa,
)


IAM_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-IAM-001",
            name="root_mfa",
            data_source="root_mfa",
            collection_mode="single",
            check_arguments=["root_mfa_enabled"],
            check=check_root_mfa,
            build_finding=build_root_mfa_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-IAM-002",
            name="user_mfa",
            data_source="iam_users",
            collection_mode="multiple",
            check_arguments=[
                "username",
                "mfa_devices",
            ],
            check=check_user_mfa,
            build_finding=build_user_mfa_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-IAM-003",
            name="access_key_age",
            data_source="iam_access_keys",
            collection_mode="multiple",
            check_arguments=[
                "username",
                "access_key_id",
                "status",
                "created_at",
                "current_time",
            ],
            check=check_access_key_age,
            build_finding=build_access_key_age_finding,
        ),
    ]
)
