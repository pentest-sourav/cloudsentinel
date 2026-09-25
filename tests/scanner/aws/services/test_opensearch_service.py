from unittest.mock import Mock, call

import boto3
from botocore.exceptions import ClientError

from scanner.aws.services.opensearch import OpenSearchService
from scanner.aws.session import AWS_RETRY_CONFIG


DOMAIN_ARN = (
    "arn:aws:es:ap-south-1:"
    "123456789012:domain/cloudsentinel"
)


def make_service():
    fake_session = Mock(spec=boto3.Session)
    fake_client = Mock()

    fake_session.client.return_value = fake_client

    service = OpenSearchService(fake_session)

    return service, fake_session, fake_client


def test_service_uses_centralized_retry_config():
    fake_session = Mock(spec=boto3.Session)
    fake_client = Mock()

    fake_session.client.return_value = fake_client

    service = OpenSearchService(fake_session)

    assert service.opensearch_client is fake_client

    fake_session.client.assert_called_once_with(
        "opensearch",
        config=AWS_RETRY_CONFIG,
    )


def test_list_domain_names():
    service, _, client = make_service()

    client.list_domain_names.return_value = {
        "DomainNames": [
            {"DomainName": "cloudsentinel-one"},
            {"DomainName": "cloudsentinel-two"},
        ]
    }

    assert service.list_domain_names() == [
        "cloudsentinel-one",
        "cloudsentinel-two",
    ]


def test_list_domain_names_handles_pagination():
    service, _, client = make_service()

    client.list_domain_names.side_effect = [
        {
            "DomainNames": [
                {"DomainName": "cloudsentinel-one"},
            ],
            "NextToken": "page-two",
        },
        {
            "DomainNames": [
                {"DomainName": "cloudsentinel-two"},
            ],
        },
    ]

    assert service.list_domain_names() == [
        "cloudsentinel-one",
        "cloudsentinel-two",
    ]

    assert client.list_domain_names.call_args_list == [
        call(),
        call(NextToken="page-two"),
    ]


def test_list_domain_names_ignores_invalid_entries():
    service, _, client = make_service()

    client.list_domain_names.return_value = {
        "DomainNames": [
            {"DomainName": "valid"},
            {},
            {"DomainName": ""},
            "invalid",
        ]
    }

    assert service.list_domain_names() == ["valid"]


def test_list_domain_names_returns_empty_when_missing():
    service, _, client = make_service()

    client.list_domain_names.return_value = {}

    assert service.list_domain_names() == []


def test_list_domain_names_handles_client_error():
    service, _, client = make_service()

    client.list_domain_names.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListDomainNames",
    )

    try:
        service.list_domain_names()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "OpenSearch domain discovery failed" in str(exc)
        assert "AccessDenied" in str(exc)


def test_describe_domain():
    service, _, client = make_service()

    client.describe_domain.return_value = {
        "DomainStatus": {
            "DomainName": "cloudsentinel",
            "ARN": DOMAIN_ARN,
            "DomainId": "domain-id",
        }
    }

    assert service.describe_domain("cloudsentinel") == {
        "DomainName": "cloudsentinel",
        "ARN": DOMAIN_ARN,
        "DomainId": "domain-id",
    }

    client.describe_domain.assert_called_once_with(
        DomainName="cloudsentinel",
    )


def test_describe_domain_returns_empty_when_missing():
    service, _, client = make_service()

    client.describe_domain.return_value = {}

    assert service.describe_domain("cloudsentinel") == {}


def test_describe_domain_handles_client_error():
    service, _, client = make_service()

    client.describe_domain.side_effect = ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Domain not found",
            }
        },
        "DescribeDomain",
    )

    try:
        service.describe_domain("cloudsentinel")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "ResourceNotFoundException" in str(exc)


def test_list_tags():
    service, _, client = make_service()

    client.list_tags.return_value = {
        "TagList": [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ]
    }

    assert service.list_tags(DOMAIN_ARN) == [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    client.list_tags.assert_called_once_with(
        ARN=DOMAIN_ARN,
    )


def test_list_tags_returns_empty_when_missing():
    service, _, client = make_service()

    client.list_tags.return_value = {}

    assert service.list_tags(DOMAIN_ARN) == []


def test_list_tags_handles_client_error():
    service, _, client = make_service()

    client.list_tags.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListTags",
    )

    try:
        service.list_tags(DOMAIN_ARN)
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "AccessDenied" in str(exc)
