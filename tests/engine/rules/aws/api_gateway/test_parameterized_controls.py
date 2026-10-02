from engine.rules.aws.api_gateway.execution_logging import (
    check_api_gateway_execution_logging,
)
from engine.rules.aws.api_gateway.route_authorization import (
    check_api_gateway_route_authorization,
)


def test_execution_logging_default_accepts_error():
    assert check_api_gateway_execution_logging(
        resource_id="api:prod",
        resource_arn="arn:test",
        api_protocol_type="REST",
        logging_level="ERROR",
        resource={},
    ) is None


def test_execution_logging_default_accepts_info():
    assert check_api_gateway_execution_logging(
        resource_id="api:prod",
        resource_arn="arn:test",
        api_protocol_type="REST",
        logging_level="INFO",
        resource={},
    ) is None


def test_execution_logging_parameter_requires_error():
    assert check_api_gateway_execution_logging(
        resource_id="api:prod",
        resource_arn="arn:test",
        api_protocol_type="REST",
        logging_level="INFO",
        resource={},
        required_logging_level="ERROR",
    ) is not None


def test_execution_logging_parameter_accepts_required_level():
    assert check_api_gateway_execution_logging(
        resource_id="api:prod",
        resource_arn="arn:test",
        api_protocol_type="REST",
        logging_level="ERROR",
        resource={},
        required_logging_level="ERROR",
    ) is None


def test_execution_logging_rejects_invalid_required_level():
    assert check_api_gateway_execution_logging(
        resource_id="api:prod",
        resource_arn="arn:test",
        api_protocol_type="REST",
        logging_level="ERROR",
        resource={},
        required_logging_level="DEBUG",
    ) is not None


def test_route_authorization_default_accepts_iam():
    assert check_api_gateway_route_authorization(
        resource_id="api:route",
        resource_arn="arn:test",
        authorization_type="AWS_IAM",
        resource={},
    ) is None


def test_route_authorization_default_rejects_none():
    assert check_api_gateway_route_authorization(
        resource_id="api:route",
        resource_arn="arn:test",
        authorization_type="NONE",
        resource={},
    ) is not None


def test_route_authorization_parameter_requires_jwt():
    assert check_api_gateway_route_authorization(
        resource_id="api:route",
        resource_arn="arn:test",
        authorization_type="AWS_IAM",
        resource={},
        required_authorization_type="JWT",
    ) is not None


def test_route_authorization_parameter_accepts_jwt():
    assert check_api_gateway_route_authorization(
        resource_id="api:route",
        resource_arn="arn:test",
        authorization_type="JWT",
        resource={},
        required_authorization_type="JWT",
    ) is None


def test_route_authorization_rejects_invalid_required_type():
    assert check_api_gateway_route_authorization(
        resource_id="api:route",
        resource_arn="arn:test",
        authorization_type="AWS_IAM",
        resource={},
        required_authorization_type="BASIC",
    ) is not None
