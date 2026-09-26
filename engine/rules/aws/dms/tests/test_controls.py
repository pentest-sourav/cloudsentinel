from engine.findings.model import Severity

from engine.rules.aws.dms.controls import (
    build_dms_auto_minor_upgrade_finding,
    build_dms_certificate_tags_finding,
    build_dms_endpoint_ssl_finding,
    build_dms_event_subscription_tags_finding,
    build_dms_mongodb_auth_finding,
    build_dms_multi_az_finding,
    build_dms_neptune_iam_auth_finding,
    build_dms_not_public_finding,
    build_dms_redis_tls_finding,
    build_dms_replication_instance_tags_finding,
    build_dms_source_logging_finding,
    build_dms_subnet_group_tags_finding,
    build_dms_target_logging_finding,
    check_dms_auto_minor_upgrade,
    check_dms_certificate_tags,
    check_dms_endpoint_ssl,
    check_dms_event_subscription_tags,
    check_dms_mongodb_auth,
    check_dms_multi_az,
    check_dms_neptune_iam_auth,
    check_dms_not_public,
    check_dms_redis_tls,
    check_dms_replication_instance_tags,
    check_dms_source_logging,
    check_dms_subnet_group_tags,
    check_dms_target_logging,
)


def test_dms_public_fails():
    result = check_dms_not_public(
        "ri",
        "arn:ri",
        "dms_replication_instance",
        True,
    )

    assert result is not None

    finding = build_dms_not_public_finding(result)

    assert finding.rule_id == "CS-AWS-DMS-001"
    assert finding.severity == Severity.CRITICAL


def test_dms_public_passes():
    assert check_dms_not_public(
        "ri",
        "arn:ri",
        "dms_replication_instance",
        False,
    ) is None


def test_dms_certificate_tags():
    result = check_dms_certificate_tags(
        "cert",
        "arn:cert",
        "dms_certificate",
        True,
        False,
    )

    assert result is not None
    assert (
        build_dms_certificate_tags_finding(result)
        .rule_id
        == "CS-AWS-DMS-002"
    )


def test_dms_event_subscription_tags():
    result = check_dms_event_subscription_tags(
        "event",
        "arn:event",
        "dms_event_subscription",
        True,
        False,
    )

    assert result is not None
    assert (
        build_dms_event_subscription_tags_finding(result)
        .rule_id
        == "CS-AWS-DMS-003"
    )


def test_dms_replication_instance_tags():
    result = check_dms_replication_instance_tags(
        "ri",
        "arn:ri",
        "dms_replication_instance",
        True,
        False,
    )

    assert result is not None
    assert (
        build_dms_replication_instance_tags_finding(result)
        .rule_id
        == "CS-AWS-DMS-004"
    )


def test_dms_subnet_group_tags():
    result = check_dms_subnet_group_tags(
        "subnet",
        "arn:subnet",
        "dms_replication_subnet_group",
        True,
        False,
    )

    assert result is not None
    assert (
        build_dms_subnet_group_tags_finding(result)
        .rule_id
        == "CS-AWS-DMS-005"
    )


def test_dms_auto_minor_upgrade():
    result = check_dms_auto_minor_upgrade(
        "ri",
        "arn:ri",
        "dms_replication_instance",
        False,
    )

    assert result is not None
    assert (
        build_dms_auto_minor_upgrade_finding(result)
        .rule_id
        == "CS-AWS-DMS-006"
    )


def test_dms_target_logging():
    result = check_dms_target_logging(
        "task",
        "arn:task",
        "dms_replication_task",
        True,
        {
            "TARGET_APPLY": "LOGGER_SEVERITY_DEFAULT",
            "TARGET_LOAD": "LOGGER_SEVERITY_DEBUG",
        },
    )

    assert result is None


def test_dms_target_logging_fails():
    result = check_dms_target_logging(
        "task",
        "arn:task",
        "dms_replication_task",
        False,
        {},
    )

    assert result is not None

    assert (
        build_dms_target_logging_finding(result)
        .rule_id
        == "CS-AWS-DMS-007"
    )


def test_dms_source_logging():
    result = check_dms_source_logging(
        "task",
        "arn:task",
        "dms_replication_task",
        True,
        {
            "SOURCE_CAPTURE": "LOGGER_SEVERITY_DEFAULT",
            "SOURCE_UNLOAD": "LOGGER_SEVERITY_DETAILED_DEBUG",
        },
    )

    assert result is None


def test_dms_source_logging_fails():
    result = check_dms_source_logging(
        "task",
        "arn:task",
        "dms_replication_task",
        True,
        {
            "SOURCE_CAPTURE": "LOGGER_SEVERITY_DEFAULT",
        },
    )

    assert result is not None

    assert (
        build_dms_source_logging_finding(result)
        .rule_id
        == "CS-AWS-DMS-008"
    )


def test_dms_endpoint_ssl():
    assert check_dms_endpoint_ssl(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "require",
    ) is None


def test_dms_endpoint_ssl_fails():
    result = check_dms_endpoint_ssl(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "none",
    )

    assert result is not None

    assert (
        build_dms_endpoint_ssl_finding(result)
        .rule_id
        == "CS-AWS-DMS-009"
    )


def test_dms_neptune_iam_auth():
    assert check_dms_neptune_iam_auth(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "neptune",
        "REQUIRED",
    ) is None


def test_dms_neptune_iam_auth_fails():
    result = check_dms_neptune_iam_auth(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "neptune",
        "DISABLED",
    )

    assert result is not None

    assert (
        build_dms_neptune_iam_auth_finding(result)
        .rule_id
        == "CS-AWS-DMS-010"
    )


def test_dms_mongodb_auth():
    assert check_dms_mongodb_auth(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "mongodb",
        "password",
    ) is None


def test_dms_mongodb_auth_fails():
    result = check_dms_mongodb_auth(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "mongodb",
        "no",
    )

    assert result is not None

    assert (
        build_dms_mongodb_auth_finding(result)
        .rule_id
        == "CS-AWS-DMS-011"
    )


def test_dms_redis_tls():
    assert check_dms_redis_tls(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "redis",
        "require",
    ) is None


def test_dms_redis_tls_fails():
    result = check_dms_redis_tls(
        "endpoint",
        "arn:endpoint",
        "dms_endpoint",
        "redis",
        "none",
    )

    assert result is not None

    assert (
        build_dms_redis_tls_finding(result)
        .rule_id
        == "CS-AWS-DMS-012"
    )


def test_dms_multi_az():
    assert check_dms_multi_az(
        "ri",
        "arn:ri",
        "dms_replication_instance",
        True,
    ) is None


def test_dms_multi_az_fails():
    result = check_dms_multi_az(
        "ri",
        "arn:ri",
        "dms_replication_instance",
        False,
    )

    assert result is not None

    assert (
        build_dms_multi_az_finding(result)
        .rule_id
        == "CS-AWS-DMS-013"
    )


def test_dms_tag_check_skips_unavailable_tag_data():
    assert check_dms_certificate_tags(
        "cert",
        "arn:cert",
        "dms_certificate",
        False,
        False,
    ) is None
