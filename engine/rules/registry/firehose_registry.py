from engine.rules.aws.firehose.protection import (
    build_firehose_encryption_finding,
    check_firehose_encryption,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


FIREHOSE_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-FIREHOSE-001",
            name="firehose_encryption",
            data_source="firehose_delivery_streams",
            collection_mode="multiple",
            check_arguments=[
                "delivery_stream_name",
                "encryption_status",
            ],
            check=check_firehose_encryption,
            build_finding=build_firehose_encryption_finding,
        ),
    ]
)
