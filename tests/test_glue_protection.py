from engine.findings.model import Severity
from engine.rules.aws.glue.protection import (
    build_glue_job_tags_finding,
    build_glue_ml_transform_encryption_finding,
    build_glue_spark_version_finding,
    check_glue_job_tags,
    check_glue_ml_transform_encryption,
    check_glue_spark_version,
)


def test_glue_001_untagged_job_fails():
    result = check_glue_job_tags(
        "job-1",
        False,
    )

    assert result is not None

    finding = build_glue_job_tags_finding(result)

    assert finding.rule_id == "CS-AWS-GLUE-001"
    assert finding.severity == Severity.LOW
    assert finding.resource_id == "job-1"


def test_glue_001_tagged_job_passes():
    assert (
        check_glue_job_tags(
            "job-1",
            True,
        )
        is None
    )


def test_glue_001_empty_job_name_is_safe():
    assert (
        check_glue_job_tags(
            "",
            False,
        )
        is None
    )


def test_glue_003_disabled_encryption_fails():
    result = check_glue_ml_transform_encryption(
        "transform-1",
        "DISABLED",
    )

    assert result is not None

    finding = build_glue_ml_transform_encryption_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-GLUE-003"
    assert finding.severity == Severity.MEDIUM


def test_glue_003_sse_kms_passes():
    assert (
        check_glue_ml_transform_encryption(
            "transform-1",
            "SSEKMS",
        )
        is None
    )


def test_glue_003_unknown_encryption_is_safe():
    assert (
        check_glue_ml_transform_encryption(
            "transform-1",
            None,
        )
        is None
    )


def test_glue_004_old_spark_version_fails():
    result = check_glue_spark_version(
        "job-1",
        "2.0",
        "glueetl",
    )

    assert result is not None

    finding = build_glue_spark_version_finding(result)

    assert finding.rule_id == "CS-AWS-GLUE-004"
    assert finding.severity == Severity.MEDIUM


def test_glue_004_supported_spark_version_passes():
    assert (
        check_glue_spark_version(
            "job-1",
            "6.0",
            "glueetl",
        )
        is None
    )


def test_glue_004_streaming_supported_version_passes():
    assert (
        check_glue_spark_version(
            "job-1",
            "5.1",
            "gluestreaming",
        )
        is None
    )


def test_glue_004_python_shell_is_not_evaluated():
    assert (
        check_glue_spark_version(
            "job-1",
            "1.0",
            "pythonshell",
        )
        is None
    )


def test_glue_004_unknown_version_is_safe():
    assert (
        check_glue_spark_version(
            "job-1",
            None,
            "glueetl",
        )
        is None
    )
