from engine.rules.aws.kinesis.encryption import (
    build_kinesis_encryption_finding,
    check_kinesis_encryption,
)
from engine.rules.aws.kinesis.retention import (
    build_kinesis_retention_finding,
    check_kinesis_retention,
)
from engine.rules.aws.kinesis.tagging import (
    build_kinesis_tagging_finding,
    check_kinesis_tagging,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


KINESIS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-KINESIS-001",
            name="kinesis_encryption",
            data_source="kinesis_streams",
            collection_mode="multiple",
            check_arguments=[
                "stream_arn",
                "encryption_type",
            ],
            check=check_kinesis_encryption,
            build_finding=build_kinesis_encryption_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-KINESIS-002",
            name="kinesis_tagging",
            data_source="kinesis_streams",
            collection_mode="multiple",
            check_arguments=[
                "stream_arn",
                "tags",
            ],
            check=check_kinesis_tagging,
            build_finding=build_kinesis_tagging_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-KINESIS-003",
            name="kinesis_retention",
            data_source="kinesis_streams",
            collection_mode="multiple",
            check_arguments=[
                "stream_arn",
                "retention_period_hours",
            ],
            check=check_kinesis_retention,
            build_finding=build_kinesis_retention_finding,
        ),
    ]
)
