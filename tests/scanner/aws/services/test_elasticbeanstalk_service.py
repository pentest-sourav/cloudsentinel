from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.elasticbeanstalk import (
    ElasticBeanstalkService,
)


def make_client():
    client = Mock()

    class ResourceNotFoundException(Exception):
        pass

    client.exceptions = Mock()
    client.exceptions.ResourceNotFoundException = (
        ResourceNotFoundException
    )

    return client


def test_list_environments_handles_pagination():
    session = Mock()
    client = make_client()

    client.describe_environments.side_effect = [
        {
            "Environments": [
                {
                    "EnvironmentId": "e-1",
                    "EnvironmentName": "env-one",
                }
            ],
            "NextToken": "token-1",
        },
        {
            "Environments": [
                {
                    "EnvironmentId": "e-2",
                    "EnvironmentName": "env-two",
                }
            ]
        },
    ]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.elasticbeanstalk.create_aws_client",
            lambda _session, _service: client,
        )

        service = ElasticBeanstalkService(session)

    environments = service.list_environments()

    assert [item["EnvironmentId"] for item in environments] == [
        "e-1",
        "e-2",
    ]
    assert client.describe_environments.call_count == 2


def test_list_environments_filters_non_dict_entries():
    session = Mock()
    client = make_client()

    client.describe_environments.return_value = {
        "Environments": [
            {
                "EnvironmentId": "e-1",
            },
            "invalid",
            None,
        ]
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.elasticbeanstalk.create_aws_client",
            lambda _session, _service: client,
        )

        service = ElasticBeanstalkService(session)

    assert service.list_environments() == [
        {
            "EnvironmentId": "e-1",
        }
    ]


def test_get_configuration_settings_returns_settings():
    session = Mock()
    client = make_client()

    client.describe_configuration_settings.return_value = {
        "ConfigurationSettings": [
            {
                "OptionSettings": [
                    {
                        "Namespace": (
                            "aws:elasticbeanstalk:"
                            "managedactions"
                        ),
                        "OptionName": "ManagedActionsEnabled",
                        "Value": "true",
                    }
                ]
            }
        ]
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.elasticbeanstalk.create_aws_client",
            lambda _session, _service: client,
        )

        service = ElasticBeanstalkService(session)

    result = service.get_configuration_settings(
        "env-one",
    )

    assert len(result) == 1
    assert result[0]["OptionSettings"][0]["Value"] == "true"


def test_get_configuration_settings_empty_environment_returns_empty():
    session = Mock()
    client = make_client()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.elasticbeanstalk.create_aws_client",
            lambda _session, _service: client,
        )

        service = ElasticBeanstalkService(session)

    assert service.get_configuration_settings("") == []
    client.describe_configuration_settings.assert_not_called()


def test_list_environments_wraps_client_error():
    session = Mock()
    client = make_client()

    client.describe_environments.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "DescribeEnvironments",
    )

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.elasticbeanstalk.create_aws_client",
            lambda _session, _service: client,
        )

        service = ElasticBeanstalkService(session)

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.list_environments()
