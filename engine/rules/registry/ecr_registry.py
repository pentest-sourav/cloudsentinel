from engine.rules.aws.ecr.customer_managed_kms import (
    build_ecr_customer_managed_kms_finding,
    check_ecr_customer_managed_kms,
)
from engine.rules.aws.ecr.image_scanning import (
    build_ecr_image_scanning_finding,
    check_ecr_image_scanning,
)
from engine.rules.aws.ecr.lifecycle_policy import (
    build_ecr_lifecycle_policy_finding,
    check_ecr_lifecycle_policy,
)
from engine.rules.aws.ecr.tag_immutability import (
    build_ecr_tag_immutability_finding,
    check_ecr_tag_immutability,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


ECR_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-ECR-001",
            name="ecr_image_scanning",
            data_source="ecr_repositories",
            collection_mode="multiple",
            check_arguments=[
                "repository_name",
                "scan_on_push",
                "registry_scan_type",
                "registry_scan_rules",
            ],
            check=check_ecr_image_scanning,
            build_finding=build_ecr_image_scanning_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-ECR-002",
            name="ecr_tag_immutability",
            data_source="ecr_repositories",
            collection_mode="multiple",
            check_arguments=[
                "repository_name",
                "image_tag_mutability",
                "image_tag_mutability_exclusion_filters",
            ],
            check=check_ecr_tag_immutability,
            build_finding=build_ecr_tag_immutability_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-ECR-003",
            name="ecr_lifecycle_policy",
            data_source="ecr_repositories",
            collection_mode="multiple",
            check_arguments=[
                "repository_name",
                "lifecycle_policy",
            ],
            check=check_ecr_lifecycle_policy,
            build_finding=build_ecr_lifecycle_policy_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-ECR-004",
            name="ecr_customer_managed_kms",
            data_source="ecr_repositories",
            collection_mode="multiple",
            check_arguments=[
                "repository_name",
                "encryption_type",
                "kms_key",
                "kms_key_manager",
            ],
            check=check_ecr_customer_managed_kms,
            build_finding=build_ecr_customer_managed_kms_finding,
        ),
    ]
)
