from engine.rules.aws.sqs.encryption import (
    build_sqs_encryption_finding,
    check_sqs_encryption,
)
from engine.rules.aws.sqs.public_access import (
    build_sqs_public_access_finding,
    check_sqs_public_access,
)
from engine.rules.aws.sqs.tagging import (
    build_sqs_tagging_finding,
    check_sqs_tagging,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


SQS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SQS-001",
            name="sqs_encryption",
            data_source="sqs_queues",
            collection_mode="multiple",
            check_arguments=[
                "queue_arn",
                "kms_master_key_id",
                "sqs_managed_sse_enabled",
            ],
            check=check_sqs_encryption,
            build_finding=build_sqs_encryption_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SQS-002",
            name="sqs_tagging",
            data_source="sqs_queues",
            collection_mode="multiple",
            check_arguments=[
                "queue_arn",
                "tags",
            ],
            check=check_sqs_tagging,
            build_finding=build_sqs_tagging_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SQS-003",
            name="sqs_public_access",
            data_source="sqs_queues",
            collection_mode="multiple",
            check_arguments=[
                "queue_arn",
                "policy",
            ],
            check=check_sqs_public_access,
            build_finding=build_sqs_public_access_finding,
        ),
    ]
)
