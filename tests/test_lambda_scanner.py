from unittest.mock import MagicMock

from scanner.aws.scanners.lambda_scanner import LambdaScanner


def test_lambda_scanner_detects_public_function_url():
    service = MagicMock()

    service.list_functions.return_value = [
        {
            "FunctionName": "public-function",
            "FunctionArn": (
                "arn:aws:lambda:eu-north-1:997139435592:"
                "function:public-function"
            ),
            "Runtime": "python3.12",
            "Role": "arn:aws:iam::997139435592:role/test-role",
            "Handler": "app.lambda_handler",
            "CodeSize": 1000,
            "Timeout": 30,
            "MemorySize": 128,
            "Environment": {},
        }
    ]

    service.get_function_url_config.return_value = {
        "function_url": (
            "https://public-function.lambda-url.eu-north-1.on.aws/"
        ),
        "auth_type": "NONE",
        "creation_time": "2026-09-19T00:00:00.000+0000",
        "last_modified_time": "2026-09-19T00:00:00.000+0000",
    }

    scanner = LambdaScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-LAMBDA-001"
    assert finding.severity.value == "high"
    assert finding.resource_id == "public-function"
    assert finding.evidence["auth_type"] == "NONE"
    assert finding.evidence["internet_exposed"] is True


def test_lambda_scanner_ignores_authenticated_function_url():
    service = MagicMock()

    service.list_functions.return_value = [
        {
            "FunctionName": "private-function",
            "Runtime": "python3.12",
        }
    ]

    service.get_function_url_config.return_value = {
        "function_url": (
            "https://private-function.lambda-url.eu-north-1.on.aws/"
        ),
        "auth_type": "AWS_IAM",
    }

    scanner = LambdaScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_lambda_scanner_handles_no_functions():
    service = MagicMock()

    service.list_functions.return_value = []

    scanner = LambdaScanner(service)

    findings = scanner.scan()

    assert findings == []
