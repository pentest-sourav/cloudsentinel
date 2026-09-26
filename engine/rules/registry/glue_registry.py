from engine.rules.aws.glue.protection import (
    build_glue_job_tags_finding,
    build_glue_ml_transform_encryption_finding,
    build_glue_spark_version_finding,
    check_glue_job_tags,
    check_glue_ml_transform_encryption,
    check_glue_spark_version,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


GLUE_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-GLUE-001",
            name="glue_job_tags",
            data_source="glue_jobs",
            collection_mode="multiple",
            check_arguments=[
                "job_name",
                "has_non_system_tags",
            ],
            check=check_glue_job_tags,
            build_finding=build_glue_job_tags_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GLUE-003",
            name="glue_ml_transform_encryption",
            data_source="glue_ml_transforms",
            collection_mode="multiple",
            check_arguments=[
                "transform_id",
                "encryption_mode",
            ],
            check=check_glue_ml_transform_encryption,
            build_finding=(
                build_glue_ml_transform_encryption_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-GLUE-004",
            name="glue_spark_version",
            data_source="glue_jobs",
            collection_mode="multiple",
            check_arguments=[
                "job_name",
                "glue_version",
                "command_name",
            ],
            check=check_glue_spark_version,
            build_finding=build_glue_spark_version_finding,
        ),
    ]
)
