from unittest.mock import Mock

from scanner.aws.collectors.inspector import (
    InspectorDataCollector,
)


def test_collect_account_status_normalizes_account():
    service = Mock()

    service.get_account_status.return_value = {
        "account_id": "123456789012",
        "account_status": "ENABLED",
        "ec2_status": "ENABLED",
        "ecr_status": "DISABLED",
        "lambda_status": "ENABLED",
        "lambda_code_status": "DISABLED",
    }

    collector = InspectorDataCollector(service)

    result = collector.collect_account_status()

    assert result == [
        {
            "resource_id": "123456789012",
            "account_id": "123456789012",
            "account_status": "ENABLED",
            "account_error_code": None,
            "account_error_message": None,
            "ec2_status": "ENABLED",
            "ec2_error_code": None,
            "ec2_error_message": None,
            "ecr_status": "DISABLED",
            "ecr_error_code": None,
            "ecr_error_message": None,
            "lambda_status": "ENABLED",
            "lambda_error_code": None,
            "lambda_error_message": None,
            "lambda_code_status": "DISABLED",
            "lambda_code_error_code": None,
            "lambda_code_error_message": None,
        }
    ]


def test_collect_account_status_caches_service_call():
    service = Mock()

    service.get_account_status.return_value = {
        "account_id": "123456789012",
        "ec2_status": "ENABLED",
        "ecr_status": "ENABLED",
        "lambda_status": "ENABLED",
        "lambda_code_status": "ENABLED",
    }

    collector = InspectorDataCollector(service)

    collector.collect_account_status()
    collector.collect_account_status()

    service.get_account_status.assert_called_once()


def test_collect_account_status_skips_missing_account_id():
    service = Mock()

    service.get_account_status.return_value = {
        "account_id": None,
        "ec2_status": "ENABLED",
    }

    collector = InspectorDataCollector(service)

    assert collector.collect_account_status() == []
