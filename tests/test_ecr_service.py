from unittest.mock import MagicMock

import pytest

from scanner.aws.services.ecr import ECRService


def test_ecr_service_lists_all_repositories():
    service = ECRService.__new__(ECRService)
    service.ecr_client = MagicMock()
    service.kms_client = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "repositories": [
                {"repositoryName": "repo-1"},
            ]
        },
        {
            "repositories": [
                {"repositoryName": "repo-2"},
            ]
        },
    ]

    service.ecr_client.get_paginator.return_value = paginator

    result = service.list_repositories()

    assert result == [
        {"repositoryName": "repo-1"},
        {"repositoryName": "repo-2"},
    ]

    service.ecr_client.get_paginator.assert_called_once_with(
        "describe_repositories"
    )


def test_ecr_service_gets_registry_scanning_configuration():
    service = ECRService.__new__(ECRService)
    service.ecr_client = MagicMock()
    service.kms_client = MagicMock()

    service.ecr_client.get_registry_scanning_configuration.return_value = {
        "scanningConfiguration": {
            "scanType": "ENHANCED",
            "rules": [],
        }
    }

    result = service.get_registry_scanning_configuration()

    assert result == {
        "scanType": "ENHANCED",
        "rules": [],
    }


def test_ecr_service_returns_none_when_lifecycle_policy_missing():
    service = ECRService.__new__(ECRService)
    service.ecr_client = MagicMock()
    service.kms_client = MagicMock()

    service.ecr_client.exceptions.LifecyclePolicyNotFoundException = (
        type("LifecyclePolicyNotFoundException", (Exception,), {})
    )

    service.ecr_client.get_lifecycle_policy.side_effect = (
        service.ecr_client.exceptions.LifecyclePolicyNotFoundException()
    )

    assert service.get_lifecycle_policy("test") is None


def test_ecr_service_describes_kms_key():
    service = ECRService.__new__(ECRService)
    service.ecr_client = MagicMock()
    service.kms_client = MagicMock()

    service.kms_client.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-1",
            "KeyManager": "CUSTOMER",
        }
    }

    result = service.describe_kms_key("key-1")

    assert result == {
        "KeyId": "key-1",
        "KeyManager": "CUSTOMER",
    }

    service.kms_client.describe_key.assert_called_once_with(
        KeyId="key-1"
    )
