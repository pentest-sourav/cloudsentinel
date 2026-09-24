from engine.rules.aws.lambda_rules.environment_secret import (
    build_lambda_environment_secret_finding,
    check_lambda_environment_secret,
)


def test_lambda_008_detects_api_key():
    result = check_lambda_environment_secret(
        function_name="api-function",
        environment_variables={
            "APP_ENV": "production",
            "API_KEY": "super-secret-value",
        },
    )

    assert result is not None
    assert result.function_name == "api-function"
    assert result.variable_name == "API_KEY"
    assert result.matched_pattern == "API_KEY"


def test_lambda_008_detects_database_password():
    result = check_lambda_environment_secret(
        function_name="database-function",
        environment_variables={
            "DB_PASSWORD": "very-secret-value",
        },
    )

    assert result is not None
    assert result.variable_name == "DB_PASSWORD"
    assert result.matched_pattern == "PASSWORD"


def test_lambda_008_detects_private_key():
    result = check_lambda_environment_secret(
        function_name="crypto-function",
        environment_variables={
            "PRIVATE_KEY": "private-key-value",
        },
    )

    assert result is not None
    assert result.variable_name == "PRIVATE_KEY"
    assert result.matched_pattern == "PRIVATE_KEY"


def test_lambda_008_ignores_normal_environment_variables():
    result = check_lambda_environment_secret(
        function_name="normal-function",
        environment_variables={
            "APP_ENV": "production",
            "API_URL": "https://example.com",
            "REGION": "eu-north-1",
            "KEY_NAME": "application-key",
            "PUBLIC_KEY": "public-key-value",
        },
    )

    assert result is None


def test_lambda_008_handles_missing_environment_variables():
    result = check_lambda_environment_secret(
        function_name="empty-function",
        environment_variables=None,
    )

    assert result is None


def test_lambda_008_handles_empty_environment_variables():
    result = check_lambda_environment_secret(
        function_name="empty-function",
        environment_variables={},
    )

    assert result is None


def test_lambda_008_does_not_expose_secret_value():
    result = check_lambda_environment_secret(
        function_name="secret-function",
        environment_variables={
            "API_KEY": "do-not-expose-this-value",
        },
    )

    assert result is not None

    finding = build_lambda_environment_secret_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-008"
    assert finding.severity.value == "high"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "secret-function"

    assert finding.evidence["variable_name"] == "API_KEY"
    assert finding.evidence["matched_pattern"] == "API_KEY"

    assert "do-not-expose-this-value" not in str(finding.evidence)
    assert "do-not-expose-this-value" not in finding.description
    assert "do-not-expose-this-value" not in finding.remediation


def test_lambda_008_detects_case_insensitive_names():
    result = check_lambda_environment_secret(
        function_name="case-function",
        environment_variables={
            "database_password": "secret-value",
        },
    )

    assert result is not None
    assert result.variable_name == "database_password"
    assert result.matched_pattern == "PASSWORD"
