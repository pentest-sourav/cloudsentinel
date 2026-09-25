from unittest.mock import Mock

import pytest

from scanner.aws.services.acm import ACMService


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = ACMService(session)

    return service, session, client


def test_init_creates_acm_client():
    service, session, client = make_service()

    assert service.acm_client is client
    session.client.assert_called_once()


def test_list_certificates_paginates():
    service, _, client = make_service()

    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "CertificateSummaryList": [
                {
                    "CertificateArn": "arn:cert:a",
                    "DomainName": "example.com",
                }
            ]
        },
        {
            "CertificateSummaryList": [
                {
                    "CertificateArn": "arn:cert:b",
                    "DomainName": "api.example.com",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    result = service.list_certificates()

    assert [
        item["CertificateArn"]
        for item in result
    ] == [
        "arn:cert:a",
        "arn:cert:b",
    ]


def test_describe_certificate_returns_metadata():
    service, _, client = make_service()

    client.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:cert:a",
            "DomainName": "example.com",
            "KeyAlgorithm": "RSA_2048",
        }
    }

    result = service.describe_certificate(
        "arn:cert:a"
    )

    assert result["CertificateArn"] == "arn:cert:a"
    assert result["KeyAlgorithm"] == "RSA_2048"


def test_list_tags_returns_tags():
    service, _, client = make_service()

    client.list_tags_for_certificate.return_value = {
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ]
    }

    result = service.list_tags(
        "arn:cert:a"
    )

    assert result == [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]


def test_sdk_error_is_wrapped():
    service, _, client = make_service()

    client.describe_certificate.side_effect = Exception(
        "boom"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during ACM",
    ):
        service.describe_certificate(
            "arn:cert:a"
        )
