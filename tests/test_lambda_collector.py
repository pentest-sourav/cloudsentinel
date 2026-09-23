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
            "PackageType": "Zip",
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
            "VpcConfig": {
                "VpcId": "vpc-12345678",
                "SubnetIds": [
                    "subnet-a",
                    "subnet-b",
                ],
                "SecurityGroupIds": ["sg-12345678"],
            },
            "TracingConfig": {
                "Mode": "Active",
            },
        }
    ]

    service.get_function_url_config.return_value = {
        "function_url": (
            "https://example.lambda-url.eu-north-1.on.aws/"
        ),
        "auth_type": "NONE",
        "creation_time": "2026-09-19T00:00:00.000+0000",
        "last_modified_time": "2026-09-19T00:00:00.000+0000",
    }

    service.get_function_policy.return_value = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [],
        },
        "revision_id": "revision-1",
    }

    service.list_event_source_mappings.return_value = []

    service.get_subnet_availability_zones.return_value = {
        "subnet-a": "eu-north-1a",
        "subnet-b": "eu-north-1b",
    }

    collector = LambdaDataCollector(service)

    functions = collector.collect_functions()

    assert len(functions) == 1

    function = functions[0]

    assert function["function_name"] == "cloudsentinel-test"
    assert function["runtime"] == "python3.12"
    assert function["package_type"] == "Zip"
    assert function["handler"] == "app.lambda_handler"
    assert function["timeout"] == 30
    assert function["memory_size"] == 256
    assert function["environment_variables"]["APP_ENV"] == "test"

    assert (
        function["function_url"]
        == "https://example.lambda-url.eu-north-1.on.aws/"
    )
    assert function["url_auth_type"] == "NONE"

    assert function["function_policy"] == {
        "Version": "2012-10-17",
        "Statement": [],
    }
    assert function["function_policy_revision_id"] == "revision-1"

    assert function["vpc_id"] == "vpc-12345678"
    assert function["subnet_ids"] == [
        "subnet-a",
        "subnet-b",
    ]
    assert function["subnet_availability_zones"] == {
        "subnet-a": "eu-north-1a",
        "subnet-b": "eu-north-1b",
    }

    assert function["tracing_mode"] == "Active"
    assert function["event_source_mappings"] == []

    service.get_function_policy.assert_called_once_with(
        "cloudsentinel-test"
    )
    service.list_event_source_mappings.assert_called_once_with(
        "cloudsentinel-test"
    )
    service.get_subnet_availability_zones.assert_called_once_with(
        [
            "subnet-a",
            "subnet-b",
        ]
    )


def test_lambda_collector_handles_function_without_url_and_policy():
    service = MagicMock()

    service.list_functions.return_value = [
        {
            "FunctionName": "private-function",
            "Runtime": "python3.12",
        }
    ]

    service.get_function_url_config.return_value = None
    service.get_function_policy.return_value = None
    service.list_event_source_mappings.return_value = []

    collector = LambdaDataCollector(service)

    functions = collector.collect_functions()

    assert len(functions) == 1

    function = functions[0]

    assert function["function_name"] == "private-function"
    assert function["function_url"] is None
    assert function["url_auth_type"] is None
    assert function["function_policy"] is None
    assert function["function_policy_revision_id"] is None

    assert function["package_type"] is None
    assert function["vpc_id"] is None
    assert function["subnet_ids"] == []
    assert function["subnet_availability_zones"] == {}
    assert function["tracing_mode"] is None
    assert function["event_source_mappings"] == []
