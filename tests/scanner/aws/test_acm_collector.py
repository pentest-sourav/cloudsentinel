from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.collectors.acm import ACMDataCollector


def make_service():
    service = Mock()

    service.list_certificates.return_value = [
        {
            "CertificateArn": "arn:cert:a",
            "DomainName": "example.com",
            "Status": "ISSUED",
        }
    ]

    service.describe_certificate.return_value = {
        "CertificateArn": "arn:cert:a",
        "DomainName": "example.com",
        "Status": "ISSUED",
        "Type": "AMAZON_ISSUED",
        "KeyAlgorithm": "RSA_2048",
        "NotBefore": datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        "NotAfter": datetime(
            2026,
            12,
            31,
            tzinfo=timezone.utc,
        ),
        "RenewalEligibility": "ELIGIBLE",
    }

    service.list_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    return service


def test_collect_certificates_normalizes_metadata():
    service = make_service()

    collector = ACMDataCollector(service)

    result = collector.collect_certificates()

    assert len(result) == 1

    certificate = result[0]

    assert certificate["resource_id"] == "arn:cert:a"
    assert certificate["domain_name"] == "example.com"
    assert certificate["key_algorithm"] == "RSA_2048"
    assert certificate["renewal_eligibility"] == "ELIGIBLE"
    assert certificate["tags"] == [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]


def test_collector_caches_api_calls():
    service = make_service()

    collector = ACMDataCollector(service)

    first = collector.collect_certificates()
    second = collector.collect_certificates()

    assert first is not second

    service.list_certificates.assert_called_once()
    service.describe_certificate.assert_called_once()
    service.list_tags.assert_called_once()
