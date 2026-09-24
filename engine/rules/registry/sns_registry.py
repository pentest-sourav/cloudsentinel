from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.sns.delivery_status import (
    build_sns_delivery_status_finding,
    check_sns_delivery_status,
)
from engine.rules.aws.sns.encryption import (
    build_sns_encryption_finding,
    check_sns_encryption,
)
from engine.rules.aws.sns.public_access import (
    build_sns_public_access_finding,
    check_sns_public_access,
)
from engine.rules.aws.sns.tagging import (
    build_sns_tagging_finding,
    check_sns_tagging,
)


SNS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SNS-001",
            name="public_access",
            data_source="sns_security",
            collection_mode="multiple",
            check_arguments=[
                "topic_arn",
                "policy",
            ],
            check=check_sns_public_access,
            build_finding=build_sns_public_access_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SNS-002",
            name="encryption",
            data_source="sns_security",
            collection_mode="multiple",
            check_arguments=[
                "topic_arn",
                "attributes",
            ],
            check=check_sns_encryption,
            build_finding=build_sns_encryption_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SNS-003",
            name="delivery_status",
            data_source="sns_security",
            collection_mode="multiple",
            check_arguments=[
                "topic_arn",
                "attributes",
            ],
            check=check_sns_delivery_status,
            build_finding=build_sns_delivery_status_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SNS-004",
            name="tagging",
            data_source="sns_security",
            collection_mode="multiple",
            check_arguments=[
                "topic_arn",
                "tags",
            ],
            check=check_sns_tagging,
            build_finding=build_sns_tagging_finding,
        ),
    ]
)
