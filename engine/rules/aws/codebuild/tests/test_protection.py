from engine.rules.aws.codebuild.protection import (
    check_cleartext_credentials,
    check_logging_configuration,
    check_report_group_export_encryption,
    check_s3_logs_encryption,
    check_source_url_credentials,
)


def test_source_url_with_userinfo_fails():
    result = check_source_url_credentials(
        "arn:project",
        "project-a",
        None,
        "https://user:password@bitbucket.org/org/repo",
        "BITBUCKET",
    )

    assert result is not None


def test_source_url_without_userinfo_passes():
    result = check_source_url_credentials(
        "arn:project",
        "project-a",
        None,
        "https://bitbucket.org/org/repo",
        "BITBUCKET",
    )

    assert result is None


def test_non_bitbucket_source_is_not_evaluated():
    result = check_source_url_credentials(
        "arn:project",
        "project-a",
        None,
        "https://user:password@github.com/org/repo",
        "GITHUB",
    )

    assert result is None


def test_cleartext_access_key_fails():
    result = check_cleartext_credentials(
        "arn:project",
        "project-a",
        "AWS_ACCESS_KEY_ID",
        "PLAINTEXT",
    )

    assert result is not None


def test_cleartext_secret_key_fails():
    result = check_cleartext_credentials(
        "arn:project",
        "project-a",
        "AWS_SECRET_ACCESS_KEY",
        "PLAINTEXT",
    )

    assert result is not None


def test_other_environment_variable_passes():
    result = check_cleartext_credentials(
        "arn:project",
        "project-a",
        "NORMAL_VAR",
        "PLAINTEXT",
    )

    assert result is None


def test_encrypted_s3_logs_pass():
    result = check_s3_logs_encryption(
        "arn:project",
        "project-a",
        "ENABLED",
        "arn:aws:s3:::logs",
        False,
    )

    assert result is None


def test_unencrypted_s3_logs_fail():
    result = check_s3_logs_encryption(
        "arn:project",
        "project-a",
        "ENABLED",
        "arn:aws:s3:::logs",
        True,
    )

    assert result is not None


def test_disabled_s3_logs_are_not_evaluated_for_encryption():
    result = check_s3_logs_encryption(
        "arn:project",
        "project-a",
        "DISABLED",
        None,
        True,
    )

    assert result is None


def test_cloudwatch_logging_passes():
    result = check_logging_configuration(
        "arn:project",
        "project-a",
        "ENABLED",
        "DISABLED",
    )

    assert result is None


def test_s3_logging_passes():
    result = check_logging_configuration(
        "arn:project",
        "project-a",
        "DISABLED",
        "ENABLED",
    )

    assert result is None


def test_no_logging_fails():
    result = check_logging_configuration(
        "arn:project",
        "project-a",
        "DISABLED",
        "DISABLED",
    )

    assert result is not None


def test_report_group_encrypted_passes():
    result = check_report_group_export_encryption(
        "arn:group",
        "group-a",
        "S3",
        "reports",
        False,
    )

    assert result is None


def test_report_group_unencrypted_s3_export_fails():
    result = check_report_group_export_encryption(
        "arn:group",
        "group-a",
        "S3",
        "reports",
        True,
    )

    assert result is not None


def test_report_group_no_export_passes():
    result = check_report_group_export_encryption(
        "arn:group",
        "group-a",
        "NO_EXPORT",
        None,
        True,
    )

    assert result is None
