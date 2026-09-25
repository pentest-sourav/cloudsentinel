from engine.findings.model import Severity

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


def test_endpoint_public_access_passes_when_disabled():
    assert (
        check_eks_endpoint_public_access(
            resource_id="cluster-a",
            resource_arn="arn:cluster:a",
            endpoint_public_access=False,
        )
        is None
    )


def test_endpoint_public_access_fails_when_enabled():
    result = check_eks_endpoint_public_access(
        resource_id="cluster-a",
        resource_arn="arn:cluster:a",
        endpoint_public_access=True,
    )

    finding = build_eks_endpoint_public_access_finding(result)

    assert finding.rule_id == "CS-AWS-EKS-001"
    assert finding.severity == Severity.HIGH


def test_supported_version_passes_at_threshold():
    assert (
        check_eks_supported_version(
            resource_id="cluster-a",
            resource_arn="arn:cluster:a",
            version="1.34",
        )
        is None
    )


def test_supported_version_fails_below_threshold():
    result = check_eks_supported_version(
        resource_id="cluster-a",
        resource_arn="arn:cluster:a",
        version="1.33",
    )

    finding = build_eks_supported_version_finding(result)

    assert finding.rule_id == "CS-AWS-EKS-002"
    assert finding.severity == Severity.HIGH


def test_cluster_tagging_passes_with_non_system_tag():
    assert (
        check_eks_cluster_tagging(
            resource_id="cluster-a",
            resource_arn="arn:cluster:a",
            tags={"Environment": "prod"},
        )
        is None
    )


def test_cluster_tagging_fails_with_only_system_tags():
    result = check_eks_cluster_tagging(
        resource_id="cluster-a",
        resource_arn="arn:cluster:a",
        tags={"aws:createdBy": "eks"},
    )

    finding = build_eks_cluster_tagging_finding(result)

    assert finding.rule_id == "CS-AWS-EKS-006"
    assert finding.severity == Severity.LOW


def test_identity_provider_tagging_passes_with_tag():
    assert (
        check_eks_identity_provider_tagging(
            resource_id="oidc-a",
            resource_arn="arn:oidc:a",
            cluster_name="cluster-a",
            provider_name="github",
            tags={"Owner": "security"},
        )
        is None
    )


def test_identity_provider_tagging_fails_without_tag():
    result = check_eks_identity_provider_tagging(
        resource_id="oidc-a",
        resource_arn="arn:oidc:a",
        cluster_name="cluster-a",
        provider_name="github",
        tags={},
    )

    finding = (
        build_eks_identity_provider_tagging_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-EKS-007"
    assert finding.severity == Severity.LOW


def test_audit_logging_passes_when_audit_enabled():
    assert (
        check_eks_audit_logging(
            resource_id="cluster-a",
            resource_arn="arn:cluster:a",
            cluster_logging=[
                {
                    "types": ["audit"],
                    "enabled": True,
                }
            ],
        )
        is None
    )


def test_audit_logging_fails_when_audit_disabled():
    result = check_eks_audit_logging(
        resource_id="cluster-a",
        resource_arn="arn:cluster:a",
        cluster_logging=[
            {
                "types": ["audit"],
                "enabled": False,
            }
        ],
    )

    finding = build_eks_audit_logging_finding(result)

    assert finding.rule_id == "CS-AWS-EKS-008"
    assert finding.severity == Severity.MEDIUM


def test_nodegroup_supported_version_passes_at_threshold():
    assert (
        check_eks_nodegroup_supported_version(
            resource_id="ng-a",
            resource_arn="arn:ng:a",
            cluster_name="cluster-a",
            version="1.34",
        )
        is None
    )


def test_nodegroup_supported_version_fails_below_threshold():
    result = check_eks_nodegroup_supported_version(
        resource_id="ng-a",
        resource_arn="arn:ng:a",
        cluster_name="cluster-a",
        version="1.33",
    )

    finding = (
        build_eks_nodegroup_supported_version_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-EKS-009"
    assert finding.severity == Severity.HIGH
