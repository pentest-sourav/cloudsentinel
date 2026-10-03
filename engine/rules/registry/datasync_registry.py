from engine.rules.aws.datasync.controls import (
    build_datasync_task_logging_finding,
    build_datasync_task_tags_finding,
    check_datasync_task_logging,
    check_datasync_task_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


DATASYNC_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-DATASYNC-001",
            name="datasync_task_logging",
            data_source="tasks",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "task_mode",
                "log_level",
                "cloudwatch_log_group_arn",
            ],
            check=check_datasync_task_logging,
            build_finding=(
                build_datasync_task_logging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-DATASYNC-002",
            name="datasync_task_tags",
            data_source="tasks",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "tag_data_available",
                "has_non_system_tags",
                "tags",
            ],
            check=check_datasync_task_tags,
            build_finding=(
                build_datasync_task_tags_finding
            ),
            parameters={
                "required_tag_keys": [],
            },
        ),
    ]
)
