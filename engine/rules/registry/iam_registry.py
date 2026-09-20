from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.iam.access_key_age import (
    build_access_key_age_finding,
    check_access_key_age,
)
from engine.rules.aws.iam.inactive_access_key import (
    build_inactive_access_key_finding,
    check_inactive_access_key,
)
from engine.rules.aws.iam.root_mfa import (
    build_root_mfa_finding,
    check_root_mfa,
)
from engine.rules.aws.iam.user_mfa import (
    build_user_mfa_finding,
    check_user_mfa,
)
from engine.rules.aws.iam.password_policy import (
    build_password_policy_finding,
    check_password_policy_minimum_length,
)
from engine.rules.aws.iam.password_policy_symbols import (
    check_password_policy_symbols,
    build_password_policy_symbols_finding,
)
from engine.rules.aws.iam.password_policy_numbers import (
    check_password_policy_numbers,
    build_password_policy_numbers_finding,
)
from engine.rules.aws.iam.password_policy_uppercase import (
    check_password_policy_uppercase,
    build_password_policy_uppercase_finding,
)
from engine.rules.aws.iam.password_policy_lowercase import (
    check_password_policy_lowercase,
    build_password_policy_lowercase_finding,
)
from engine.rules.aws.iam.password_reuse import (
    check_password_reuse,
    build_password_reuse_finding,
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
        RuleDefinition(
            rule_id="CS-AWS-IAM-004",
            name="inactive_access_key",
            data_source="iam_access_keys",
            collection_mode="multiple",
            check_arguments=[
                "username",
                "access_key_id",
                "status",
                "created_at",
            ],
            check=check_inactive_access_key,
            build_finding=build_inactive_access_key_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-IAM-005",
            name="password_policy",
            data_source="password_policy",
            collection_mode="single",
            check_arguments=[
                "minimum_password_length",
            ],
            check=check_password_policy_minimum_length,
            build_finding=build_password_policy_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-IAM-006",
            name="password_policy_symbols",
            data_source="password_policy",
            collection_mode="single",
            check_arguments=["require_symbols"],
            check=check_password_policy_symbols,
            build_finding=build_password_policy_symbols_finding,
        ),
       RuleDefinition(
            rule_id="CS-AWS-IAM-007",
            name="password_policy_numbers",
            data_source="password_policy",
            collection_mode="single",
            check_arguments=["require_numbers"],
            check=check_password_policy_numbers,
            build_finding=build_password_policy_numbers_finding,
       ),
       RuleDefinition(
           rule_id="CS-AWS-IAM-008",
           name="password_policy_uppercase",
           data_source="password_policy",
           collection_mode="single",
           check_arguments=["require_uppercase"],
           check=check_password_policy_uppercase,
           build_finding=build_password_policy_uppercase_finding,
       ),
       RuleDefinition(
           rule_id="CS-AWS-IAM-009",
           name="password_policy_lowercase",
           data_source="password_policy",
           collection_mode="single",
           check_arguments=["require_lowercase"],
           check=check_password_policy_lowercase,
           build_finding=build_password_policy_lowercase_finding,
       ),
        RuleDefinition(
            rule_id="CS-AWS-IAM-010",
            name="password_reuse",
            data_source="password_policy",
            collection_mode="single",
            check_arguments=["password_reuse_prevention"],
            check=check_password_reuse,
            build_finding=build_password_reuse_finding,
        ),
    ]
)
