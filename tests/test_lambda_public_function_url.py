from engine.rules.aws.lambda_rules.public_function_url import (
    build_public_lambda_function_url_finding,
    check_public_lambda_function_url,
)

def test_detects_public_lambda_function_url():
    result = check_public_lambda_function_url(
        function_name="public-function",
        function_url="https://public-function.lambda-url.eu-north-1.on.aws/",
        url_auth_type="NONE",
    )

    assert result is not None
    assert result.function_name == "public-function"
    assert (
        result.function_url
        == "https://public-function.lambda-url.eu-north-1.on.aws/"
    )


def test_ignores_lambda_function_without_url():
    result = check_public_lambda_function_url(
        function_name="private-function",
        function_url=None,
        url_auth_type=None,
    )

    assert result is None


def test_ignores_authenticated_lambda_function_url():
    result = check_public_lambda_function_url(
        function_name="authenticated-function",
        function_url="https://authenticated.lambda-url.eu-north-1.on.aws/",
        url_auth_type="AWS_IAM",
    )

    assert result is None


def test_builds_high_severity_finding():
    result = check_public_lambda_function_url(
        function_name="public-function",
        function_url="https://public-function.lambda-url.eu-north-1.on.aws/",
        url_auth_type="NONE",
    )

    assert result is not None

    finding = build_public_lambda_function_url_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-001"
    assert finding.severity.value == "high"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "public-function"
    assert finding.evidence["auth_type"] == "NONE"
    assert finding.evidence["internet_exposed"] is True
