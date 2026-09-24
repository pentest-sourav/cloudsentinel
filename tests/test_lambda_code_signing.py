from engine.rules.aws.lambda_rules.code_signing import (
    build_lambda_code_signing_finding,
    check_lambda_code_signing,
)


def test_lambda_007_ignores_container_image():
    result = check_lambda_code_signing(
        function_name="container-function",
        package_type="Image",
        code_signing_config_arn=None,
        code_signing_policy=None,
    )

    assert result is None


def test_lambda_007_detects_missing_code_signing_config():
    result = check_lambda_code_signing(
        function_name="unsigned-function",
        package_type="Zip",
        code_signing_config_arn=None,
        code_signing_policy=None,
    )

    assert result is not None
    assert result.function_name == "unsigned-function"


def test_lambda_007_detects_warn_mode():
    result = check_lambda_code_signing(
        function_name="warn-function",
        package_type="Zip",
        code_signing_config_arn=(
            "arn:aws:lambda:eu-north-1:123456789012:"
            "code-signing-config:csc-1234567890abcdef"
        ),
        code_signing_policy={
            "UntrustedArtifactOnDeployment": "Warn",
        },
    )

    assert result is not None


def test_lambda_007_ignores_enforce_mode():
    result = check_lambda_code_signing(
        function_name="signed-function",
        package_type="Zip",
        code_signing_config_arn=(
            "arn:aws:lambda:eu-north-1:123456789012:"
            "code-signing-config:csc-1234567890abcdef"
        ),
        code_signing_policy={
            "UntrustedArtifactOnDeployment": "Enforce",
        },
    )

    assert result is None


def test_lambda_007_builds_high_finding():
    result = check_lambda_code_signing(
        function_name="unsigned-function",
        package_type="Zip",
        code_signing_config_arn=None,
        code_signing_policy=None,
    )

    assert result is not None

    finding = build_lambda_code_signing_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-007"
    assert finding.severity.value == "high"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "unsigned-function"
    assert finding.evidence["code_signing_enforced"] is False
