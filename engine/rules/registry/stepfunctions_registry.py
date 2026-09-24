from engine.rules.aws.stepfunctions.logging import (
    build_stepfunctions_logging_finding,
    check_stepfunctions_logging,
)
from engine.rules.aws.stepfunctions.tagging import (
    build_stepfunctions_tagging_finding,
    check_stepfunctions_tagging,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


STEPFUNCTIONS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SFN-001",
            name="stepfunctions_logging",
            data_source="stepfunctions_state_machines",
            collection_mode="multiple",
            check_arguments=[
                "state_machine_arn",
                "logging_configuration",
            ],
            check=check_stepfunctions_logging,
            build_finding=(
                build_stepfunctions_logging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-SFN-002",
            name="stepfunctions_activity_tagging",
            data_source="stepfunctions_activities",
            collection_mode="multiple",
            check_arguments=[
                "activity_arn",
                "tags",
            ],
            check=check_stepfunctions_tagging,
            build_finding=(
                build_stepfunctions_tagging_finding
            ),
        ),
    ]
)
