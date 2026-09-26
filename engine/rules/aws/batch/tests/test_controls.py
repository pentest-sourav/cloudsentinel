from engine.findings.model import Severity

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


def test_batch_job_queue_passes_with_non_system_tag():
    assert check_batch_job_queue_tags(
        "queue",
        "arn:queue",
        "batch_job_queue",
        True,
        True,
    ) is None


def test_batch_job_queue_fails_without_non_system_tag():
    result = check_batch_job_queue_tags(
        "queue",
        "arn:queue",
        "batch_job_queue",
        True,
        False,
    )

    assert result is not None

    finding = build_batch_job_queue_tags_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-BATCH-001"
    assert finding.severity == Severity.LOW


def test_batch_scheduling_policy_finding():
    result = check_batch_scheduling_policy_tags(
        "policy",
        "arn:policy",
        "batch_scheduling_policy",
        True,
        False,
    )

    assert result is not None

    assert (
        build_batch_scheduling_policy_tags_finding(
            result
        ).rule_id
        == "CS-AWS-BATCH-002"
    )


def test_batch_compute_environment_finding():
    result = check_batch_compute_environment_tags(
        "env",
        "arn:env",
        "batch_compute_environment",
        True,
        False,
    )

    assert result is not None

    assert (
        build_batch_compute_environment_tags_finding(
            result
        ).rule_id
        == "CS-AWS-BATCH-003"
    )


def test_batch_compute_resources_finding():
    result = check_batch_compute_resource_tags(
        "env",
        "arn:env",
        "batch_compute_environment_resources",
        True,
        False,
        "EC2",
    )

    assert result is not None

    finding = (
        build_batch_compute_resource_tags_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-BATCH-004"

    assert (
        finding.evidence["compute_resource_type"]
        == "EC2"
    )


def test_batch_skips_when_tag_data_unavailable():
    assert check_batch_job_queue_tags(
        "queue",
        "arn:queue",
        "batch_job_queue",
        False,
        False,
    ) is None


def test_batch_skips_invalid_resource():
    assert check_batch_job_queue_tags(
        "",
        "",
        "batch_job_queue",
        True,
        False,
    ) is None
