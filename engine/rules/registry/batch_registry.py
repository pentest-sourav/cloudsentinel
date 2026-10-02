from engine.rules.aws.batch.controls import (
    build_batch_compute_environment_tags_finding,
    build_batch_compute_resource_tags_finding,
    build_batch_job_queue_tags_finding,
    build_batch_scheduling_policy_tags_finding,
    check_batch_compute_environment_tags,
    check_batch_compute_resource_tags,
    check_batch_job_queue_tags,
    check_batch_scheduling_policy_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


BATCH_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-BATCH-001",
            name="batch_job_queue_tags",
            data_source="batch_job_queues",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "tag_data_available",
                "has_non_system_tags",
                "tags",
                "required_tag_keys",
            ],
            parameters={
                "required_tag_keys": [],
            },
            check=check_batch_job_queue_tags,
            build_finding=(
                build_batch_job_queue_tags_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-BATCH-002",
            name="batch_scheduling_policy_tags",
            data_source="batch_scheduling_policies",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "tag_data_available",
                "has_non_system_tags",
                "tags",
                "required_tag_keys",
            ],
            parameters={
                "required_tag_keys": [],
            },
            check=check_batch_scheduling_policy_tags,
            build_finding=(
                build_batch_scheduling_policy_tags_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-BATCH-003",
            name="batch_compute_environment_tags",
            data_source="batch_compute_environments",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "tag_data_available",
                "has_non_system_tags",
                "tags",
                "required_tag_keys",
            ],
            parameters={
                "required_tag_keys": [],
            },
            check=check_batch_compute_environment_tags,
            build_finding=(
                build_batch_compute_environment_tags_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-BATCH-004",
            name="batch_compute_resource_tags",
            data_source="batch_compute_resource_tags",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "tag_data_available",
                "has_non_system_tags",
                "compute_resource_type",
                "tags",
                "required_tag_keys",
            ],
            parameters={
                "required_tag_keys": [],
            },
            check=check_batch_compute_resource_tags,
            build_finding=(
                build_batch_compute_resource_tags_finding
            ),
        ),
    ]
)
