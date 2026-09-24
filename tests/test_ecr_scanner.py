from unittest.mock import MagicMock

from scanner.aws.scanners.ecr import ECRScanner


def test_ecr_scanner_executes_registry():
    service = MagicMock()

    service.list_repositories.return_value = [
        {
            "repositoryName": "prod/app",
            "repositoryArn": (
                "arn:aws:ecr:us-east-1:123456789012:"
                "repository/prod/app"
            ),
            "registryId": "123456789012",
            "imageTagMutability": "MUTABLE",
            "imageScanningConfiguration": {
                "scanOnPush": False,
            },
            "encryptionConfiguration": {
                "encryptionType": "AES256",
            },
        }
    ]

    service.get_registry_scanning_configuration.return_value = {
        "scanType": "BASIC",
        "rules": [],
    }

    service.get_lifecycle_policy.return_value = None

    scanner = ECRScanner(service)

    findings = scanner.scan()

    assert len(findings) == 4

    assert {
        finding.rule_id
        for finding in findings
    } == {
        "CS-AWS-ECR-001",
        "CS-AWS-ECR-002",
        "CS-AWS-ECR-003",
        "CS-AWS-ECR-004",
    }
