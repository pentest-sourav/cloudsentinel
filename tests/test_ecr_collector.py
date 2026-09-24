from unittest.mock import MagicMock

from scanner.aws.collectors.ecr import ECRDataCollector


def test_collect_ecr_repositories_normalizes_configuration():
    service = MagicMock()

    service.list_repositories.return_value = [
        {
            "repositoryName": "prod/app",
            "repositoryArn": (
                "arn:aws:ecr:us-east-1:123456789012:"
                "repository/prod/app"
            ),
            "repositoryUri": (
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/prod/app"
            ),
            "registryId": "123456789012",
            "imageTagMutability": "IMMUTABLE",
            "imageTagMutabilityExclusionFilters": [],
            "imageScanningConfiguration": {
                "scanOnPush": False,
            },
            "encryptionConfiguration": {
                "encryptionType": "KMS",
                "kmsKey": (
                    "arn:aws:kms:us-east-1:123456789012:key/key-1"
                ),
            },
        }
    ]

    service.get_registry_scanning_configuration.return_value = {
        "scanType": "ENHANCED",
        "rules": [
            {
                "scanFrequency": "CONTINUOUS_SCAN",
                "repositoryFilters": [
                    {
                        "filter": "prod",
                        "filterType": "WILDCARD",
                    }
                ],
            }
        ],
    }

    service.get_lifecycle_policy.return_value = {
        "repositoryName": "prod/app",
        "registryId": "123456789012",
        "lifecyclePolicyText": (
            '{"rules":[{"rulePriority":1}]}'
        ),
    }

    service.describe_kms_key.return_value = {
        "KeyId": "key-1",
        "KeyManager": "CUSTOMER",
        "KeyState": "Enabled",
    }

    collector = ECRDataCollector(service)

    result = collector.collect_repositories()

    assert result == [
        {
            "repository_name": "prod/app",
            "repository_arn": (
                "arn:aws:ecr:us-east-1:123456789012:"
                "repository/prod/app"
            ),
            "repository_uri": (
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/prod/app"
            ),
            "registry_id": "123456789012",
            "image_tag_mutability": "IMMUTABLE",
            "image_tag_mutability_exclusion_filters": [],
            "scan_on_push": False,
            "encryption_type": "KMS",
            "kms_key": (
                "arn:aws:kms:us-east-1:123456789012:key/key-1"
            ),
            "kms_key_manager": "CUSTOMER",
            "registry_scan_type": "ENHANCED",
            "registry_scan_rules": [
                {
                    "scanFrequency": "CONTINUOUS_SCAN",
                    "repositoryFilters": [
                        {
                            "filter": "prod",
                            "filterType": "WILDCARD",
                        }
                    ],
                }
            ],
            "lifecycle_policy": {
                "repositoryName": "prod/app",
                "registryId": "123456789012",
                "lifecyclePolicyText": (
                    '{"rules":[{"rulePriority":1}]}'
                ),
            },
        }
    ]

    service.get_registry_scanning_configuration.assert_called_once()
    service.get_lifecycle_policy.assert_called_once_with("prod/app")
    service.describe_kms_key.assert_called_once_with(
        "arn:aws:kms:us-east-1:123456789012:key/key-1"
    )


def test_collect_ecr_repositories_does_not_query_kms_for_aes256():
    service = MagicMock()

    service.list_repositories.return_value = [
        {
            "repositoryName": "test",
            "imageScanningConfiguration": {
                "scanOnPush": True,
            },
            "encryptionConfiguration": {
                "encryptionType": "AES256",
            },
            "imageTagMutability": "IMMUTABLE",
        }
    ]

    service.get_registry_scanning_configuration.return_value = {
        "scanType": "BASIC",
        "rules": [],
    }

    service.get_lifecycle_policy.return_value = None

    collector = ECRDataCollector(service)

    result = collector.collect_repositories()

    assert result[0]["encryption_type"] == "AES256"
    assert result[0]["kms_key"] is None
    assert result[0]["kms_key_manager"] is None
    service.describe_kms_key.assert_not_called()
