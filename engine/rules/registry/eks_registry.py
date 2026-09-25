from engine.rules.aws.eks.audit_logging import (
    build_eks_audit_logging_finding,
    check_eks_audit_logging,
)
from engine.rules.aws.eks.cluster_tagging import (
    build_eks_cluster_tagging_finding,
    check_eks_cluster_tagging,
)
from engine.rules.aws.eks.endpoint_public_access import (
    build_eks_endpoint_public_access_finding,
    check_eks_endpoint_public_access,
)
from engine.rules.aws.eks.identity_provider_tagging import (
    build_eks_identity_provider_tagging_finding,
    check_eks_identity_provider_tagging,
)
from engine.rules.aws.eks.nodegroup_supported_version import (
    build_eks_nodegroup_supported_version_finding,
    check_eks_nodegroup_supported_version,
)
from engine.rules.aws.eks.supported_version import (
    build_eks_supported_version_finding,
    check_eks_supported_version,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


EKS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-EKS-001",
            name="eks_endpoint_public_access",
            data_source="eks_clusters",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "endpoint_public_access",
            ],
            check=check_eks_endpoint_public_access,
            build_finding=(
                build_eks_endpoint_public_access_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-EKS-002",
            name="eks_supported_version",
            data_source="eks_clusters",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "version",
            ],
            check=check_eks_supported_version,
            build_finding=(
                build_eks_supported_version_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-EKS-006",
            name="eks_cluster_tagging",
            data_source="eks_clusters",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "tags",
            ],
            check=check_eks_cluster_tagging,
            build_finding=(
                build_eks_cluster_tagging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-EKS-007",
            name="eks_identity_provider_tagging",
            data_source="eks_identity_provider_configs",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "cluster_name",
                "provider_name",
                "tags",
            ],
            check=check_eks_identity_provider_tagging,
            build_finding=(
                build_eks_identity_provider_tagging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-EKS-008",
            name="eks_audit_logging",
            data_source="eks_clusters",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "cluster_logging",
            ],
            check=check_eks_audit_logging,
            build_finding=(
                build_eks_audit_logging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-EKS-009",
            name="eks_nodegroup_supported_version",
            data_source="eks_nodegroups",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "cluster_name",
                "version",
            ],
            check=check_eks_nodegroup_supported_version,
            build_finding=(
                build_eks_nodegroup_supported_version_finding
            ),
        ),
    ]
)
