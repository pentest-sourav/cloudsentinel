from unittest.mock import Mock

from botocore.exceptions import ClientError

from scanner.aws.services.config import ConfigService


def test_config_service_uses_config_client():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = ConfigService(session)

    assert service.config_client is client

    assert session.client.call_count == 1
    assert session.client.call_args.args == ("config",)

    config_arg = session.client.call_args.kwargs.get(
        "config"
    )
    assert config_arg is not None


def test_describe_configuration_recorders():
    session = Mock()
    client = Mock()

    session.client.return_value = client
    client.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [
            {
                "name": "default",
                "roleARN": "arn:aws:iam::123:role/config",
            }
        ]
    }

    service = ConfigService(session)

    assert service.describe_configuration_recorders() == [
        {
            "name": "default",
            "roleARN": "arn:aws:iam::123:role/config",
        }
    ]


def test_describe_configuration_recorder_status():
    session = Mock()
    client = Mock()

    session.client.return_value = client
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [
            {
                "name": "default",
                "recording": True,
            }
        ]
    }

    service = ConfigService(session)

    assert service.describe_configuration_recorder_status() == [
        {
            "name": "default",
            "recording": True,
        }
    ]


def test_describe_configuration_recorders_handles_client_error():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.describe_configuration_recorders.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "denied",
                }
            },
            "DescribeConfigurationRecorders",
        )
    )

    service = ConfigService(session)

    try:
        service.describe_configuration_recorders()
    except RuntimeError as exc:
        assert "AccessDeniedException" in str(exc)
        assert "denied" in str(exc)
    else:
        raise AssertionError(
            "Expected RuntimeError"
        )
