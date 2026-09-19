from unittest.mock import MagicMock

from scanner.aws.collectors.lambda_collector import LambdaDataCollector


def test_lambda_collector_normalizes_function():
    service = MagicMock()

    service.list_functions.return_value = [
        {
            "FunctionName": "cloudsentinel-test",
            "FunctionArn": (
                "arn:aws:lambda:eu-north-1:997139435592:"
                "function:cloudsentinel-test"
            ),
            "Runtime": "python3.12",
            "Role": (
                "arn:aws:iam::997139435592:"
                "role/cloudsentinel-test-role"
            ),
            "Handler": "app.lambda_handler",
            "CodeSize": 12345,
            "Timeout": 30,
            "MemorySize": 256,
            "Environment": {
                "Variables": {
                    "APP_ENV": "test",
                    "API_KEY": "dummy-value",
                }
            },
            "LastModified": "2026-09-19T00:00:00.000+0000",
        }
    ]

    service.get_function_url_config.return_value = {
        "function_url": "https://example.lambda-url.eu-north-1.on.aws/",
        "auth_type": "NONE",
        "creation_time": "2026-09-19T00:00:00.000+0000",
        "last_modified_time": "2026-09-19T00:00:00.000+0000",
    }

    collector = LambdaDataCollector(service)

    functions = collector.collect_functions()

    assert len(functions) == 1

    function = functions[0]

    assert function["function_name"] == "cloudsentinel-test"
    assert function["runtime"] == "python3.12"
    assert function["handler"] == "app.lambda_handler"
    assert function["timeout"] == 30
    assert function["memory_size"] == 256
    assert function["environment_variables"]["APP_ENV"] == "test"

    assert (
        function["function_url"]
        == "https://example.lambda-url.eu-north-1.on.aws/"
    )
    assert function["url_auth_type"] == "NONE"


def test_lambda_collector_handles_function_without_url():
    service = MagicMock()

    service.list_functions.return_value = [
        {
            "FunctionName": "private-function",
            "Runtime": "python3.12",
        }
    ]

    service.get_function_url_config.return_value = None

    collector = LambdaDataCollector(service)

    functions = collector.collect_functions()

    assert len(functions) == 1

    function = functions[0]

    assert function["function_name"] == "private-function"
    assert function["function_url"] is None
    assert function["url_auth_type"] is None
