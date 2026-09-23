from engine.rules.aws.lambda_rules.public_resource_policy import (
    build_public_lambda_resource_policy_finding,
    check_public_lambda_resource_policy,
)


def test_detects_wildcard_public_lambda_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "public",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:InvokeFunction",
                "Resource": (
                    "arn:aws:lambda:eu-north-1:123456789012:"
                    "function:public-function"
                ),
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="public-function",
        function_policy=policy,
    )

    assert result is not None
    assert result.function_name == "public-function"
    assert result.statement_id == "public"


def test_detects_aws_wildcard_principal():
    policy = {
        "Statement": [
            {
                "Sid": "public",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*",
                },
                "Action": "lambda:InvokeFunction",
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="public-function",
        function_policy=policy,
    )

    assert result is not None


def test_ignores_fixed_aws_principal():
    policy = {
        "Statement": [
            {
                "Sid": "account-access",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::111122223333:root",
                },
                "Action": "lambda:InvokeFunction",
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="cross-account-function",
        function_policy=policy,
    )

    assert result is None


def test_ignores_s3_access_with_fixed_source_account():
    policy = {
        "Statement": [
            {
                "Sid": "s3-access",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com",
                },
                "Action": "lambda:InvokeFunction",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceAccount": "123456789012",
                    }
                },
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="s3-function",
        function_policy=policy,
    )

    assert result is None


def test_detects_s3_access_without_source_account():
    policy = {
        "Statement": [
            {
                "Sid": "s3-access",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com",
                },
                "Action": "lambda:InvokeFunction",
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="s3-function",
        function_policy=policy,
    )

    assert result is not None


def test_ignores_non_invoke_action():
    policy = {
        "Statement": [
            {
                "Sid": "read-access",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:GetFunction",
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="function",
        function_policy=policy,
    )

    assert result is None


def test_ignores_deny_statement():
    policy = {
        "Statement": [
            {
                "Sid": "deny-public",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "lambda:InvokeFunction",
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="function",
        function_policy=policy,
    )

    assert result is None


def test_handles_single_statement_object():
    policy = {
        "Statement": {
            "Sid": "public",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "lambda:InvokeFunction",
        }
    }

    result = check_public_lambda_resource_policy(
        function_name="function",
        function_policy=policy,
    )

    assert result is not None


def test_handles_missing_policy():
    result = check_public_lambda_resource_policy(
        function_name="function",
        function_policy=None,
    )

    assert result is None


def test_builds_critical_finding():
    policy = {
        "Statement": [
            {
                "Sid": "public",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:InvokeFunction",
            }
        ],
    }

    result = check_public_lambda_resource_policy(
        function_name="public-function",
        function_policy=policy,
    )

    assert result is not None

    finding = build_public_lambda_resource_policy_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-002"
    assert finding.severity.value == "critical"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "public-function"
    assert finding.evidence["public_access"] is True
