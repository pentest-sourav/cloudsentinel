from engine.rules.aws.eks.cluster_tagging import (
    build_eks_cluster_tagging_finding,
    check_eks_cluster_tagging,
)
from engine.rules.aws.eks.common import (
    has_required_tag_keys,
    normalize_required_tag_keys,
)
from engine.rules.aws.eks.identity_provider_tagging import (
    build_eks_identity_provider_tagging_finding,
    check_eks_identity_provider_tagging,
)


def test_required_tag_keys_accept_all_configured_keys():
    assert has_required_tag_keys(
        {
            "Environment": "prod",
            "Owner": "security",
            "aws:createdBy": "system",
        },
        ["Environment", "Owner"],
    )


def test_required_tag_keys_reject_missing_configured_key():
    assert not has_required_tag_keys(
        {
            "Environment": "prod",
        },
        ["Environment", "Owner"],
    )


def test_empty_required_tag_keys_preserves_existing_semantics():
    assert has_required_tag_keys(
        {
            "Environment": "prod",
        },
        [],
    )

    assert not has_required_tag_keys(
        {
            "aws:createdBy": "system",
        },
        [],
    )


def test_required_tag_keys_ignore_system_tag_keys():
    assert not has_required_tag_keys(
        {
            "aws:Environment": "prod",
        },
        ["aws:Environment"],
    )


def test_required_tag_keys_are_normalized_and_deduplicated():
    assert normalize_required_tag_keys(
        [
            " Environment ",
            "Environment",
            "",
            "Owner",
            "aws:system",
            123,
        ]
    ) == (
        "Environment",
        "Owner",
    )


def test_cluster_tagging_passes_when_required_keys_exist():
    assert check_eks_cluster_tagging(
        resource_id="cluster-1",
        resource_arn="arn:aws:eks:region:account:cluster/cluster-1",
        tags={
            "Environment": "prod",
            "Owner": "security",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
        ],
    ) is None


def test_cluster_tagging_fails_when_required_key_is_missing():
    result = check_eks_cluster_tagging(
        resource_id="cluster-1",
        resource_arn="arn:aws:eks:region:account:cluster/cluster-1",
        tags={
            "Environment": "prod",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
        ],
    )

    assert result is not None
    assert result.required_tag_keys == (
        "Environment",
        "Owner",
    )


def test_cluster_tagging_finding_contains_parameter_evidence():
    result = check_eks_cluster_tagging(
        resource_id="cluster-1",
        resource_arn="arn:aws:eks:region:account:cluster/cluster-1",
        tags={
            "Environment": "prod",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
        ],
    )

    assert result is not None

    finding = build_eks_cluster_tagging_finding(result)

    assert finding.rule_id == "CS-AWS-EKS-006"
    assert finding.evidence["required_tag_keys"] == [
        "Environment",
        "Owner",
    ]


def test_identity_provider_tagging_passes_when_required_keys_exist():
    assert check_eks_identity_provider_tagging(
        resource_id="provider-1",
        resource_arn="arn:aws:eks:region:account:identity-provider-config/provider-1",
        cluster_name="cluster-1",
        provider_name="oidc",
        tags={
            "Environment": "prod",
            "Owner": "security",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
        ],
    ) is None


def test_identity_provider_tagging_fails_when_required_key_is_missing():
    result = check_eks_identity_provider_tagging(
        resource_id="provider-1",
        resource_arn="arn:aws:eks:region:account:identity-provider-config/provider-1",
        cluster_name="cluster-1",
        provider_name="oidc",
        tags={
            "Environment": "prod",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
        ],
    )

    assert result is not None
    assert result.required_tag_keys == (
        "Environment",
        "Owner",
    )


def test_identity_provider_finding_contains_parameter_evidence():
    result = check_eks_identity_provider_tagging(
        resource_id="provider-1",
        resource_arn="arn:aws:eks:region:account:identity-provider-config/provider-1",
        cluster_name="cluster-1",
        provider_name="oidc",
        tags={
            "Environment": "prod",
        },
        required_tag_keys=[
            "Environment",
            "Owner",
        ],
    )

    assert result is not None

    finding = (
        build_eks_identity_provider_tagging_finding(result)
    )

    assert finding.rule_id == "CS-AWS-EKS-007"
    assert finding.evidence["required_tag_keys"] == [
        "Environment",
        "Owner",
    ]
