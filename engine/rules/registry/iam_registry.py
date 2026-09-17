from engine.rules.aws.iam.root_mfa import (
    build_root_mfa_finding,
    check_root_mfa,
)
from engine.rules.aws.iam.user_mfa import (
    build_user_mfa_finding,
    check_user_mfa,
)


IAM_RULES = [
    {
        "rule_id": "CS-AWS-IAM-001",
        "name": "root_mfa",
        "data_source": "root_mfa",
        "collection_mode": "single",
        "check_arguments": ["root_mfa_enabled"],
        "check": check_root_mfa,
        "build_finding": build_root_mfa_finding,
    },
    {
        "rule_id": "CS-AWS-IAM-002",
        "name": "user_mfa",
        "data_source": "iam_users",
        "collection_mode": "multiple",
        "check_arguments": [
            "username",
            "mfa_devices",
        ],
        "check": check_user_mfa,
        "build_finding": build_user_mfa_finding,
    },
]
