from engine.rules.aws.ecr.customer_managed_kms import (
    check_ecr_customer_managed_kms,
)
from engine.rules.aws.ecr.image_scanning import (
    check_ecr_image_scanning,
)
from engine.rules.aws.ecr.lifecycle_policy import (
    check_ecr_lifecycle_policy,
)
from engine.rules.aws.ecr.tag_immutability import (
    check_ecr_tag_immutability,
)


def test_ecr_image_scanning_passes_for_repository_scan_on_push():
    assert (
        check_ecr_image_scanning(
            repository_name="prod/app",
            scan_on_push=True,
            registry_scan_type="BASIC",
            registry_scan_rules=[],
        )
        is None
    )


def test_ecr_image_scanning_passes_for_matching_registry_scan_on_push():
    assert (
        check_ecr_image_scanning(
            repository_name="prod/app",
            scan_on_push=False,
            registry_scan_type="BASIC",
            registry_scan_rules=[
                {
                    "scanFrequency": "SCAN_ON_PUSH",
                    "repositoryFilters": [
                        {
                            "filter": "prod",
                            "filterType": "WILDCARD",
                        }
                    ],
                }
            ],
        )
        is None
    )


def test_ecr_image_scanning_passes_for_enhanced_continuous_scan():
    assert (
        check_ecr_image_scanning(
            repository_name="prod/app",
            scan_on_push=False,
            registry_scan_type="ENHANCED",
            registry_scan_rules=[
                {
                    "scanFrequency": "CONTINUOUS_SCAN",
                    "repositoryFilters": [],
                }
            ],
        )
        is None
    )


def test_ecr_image_scanning_fails_when_repository_is_manual():
    result = check_ecr_image_scanning(
        repository_name="dev/app",
        scan_on_push=False,
        registry_scan_type="BASIC",
        registry_scan_rules=[],
    )

    assert result is not None
    assert result.repository_name == "dev/app"


def test_ecr_tag_immutability_passes_for_immutable():
    assert (
        check_ecr_tag_immutability(
            repository_name="prod/app",
            image_tag_mutability="IMMUTABLE",
            image_tag_mutability_exclusion_filters=[],
        )
        is None
    )


def test_ecr_tag_immutability_fails_for_mutable():
    result = check_ecr_tag_immutability(
        repository_name="prod/app",
        image_tag_mutability="MUTABLE",
        image_tag_mutability_exclusion_filters=[],
    )

    assert result is not None


def test_ecr_tag_immutability_fails_for_exclusion_mode():
    result = check_ecr_tag_immutability(
        repository_name="prod/app",
        image_tag_mutability="IMMUTABLE_WITH_EXCLUSION",
        image_tag_mutability_exclusion_filters=[
            {
                "filter": "latest",
                "filterType": "WILDCARD",
            }
        ],
    )

    assert result is not None


def test_ecr_lifecycle_policy_passes_when_configured():
    assert (
        check_ecr_lifecycle_policy(
            repository_name="prod/app",
            lifecycle_policy={
                "lifecycle_policy_text": (
                    '{"rules":[{"rulePriority":1}]}'
                )
            },
        )
        is None
    )


def test_ecr_lifecycle_policy_fails_when_missing():
    result = check_ecr_lifecycle_policy(
        repository_name="prod/app",
        lifecycle_policy=None,
    )

    assert result is not None


def test_ecr_customer_managed_kms_passes():
    assert (
        check_ecr_customer_managed_kms(
            repository_name="prod/app",
            encryption_type="KMS",
            kms_key="arn:aws:kms:us-east-1:123456789012:key/key-1",
            kms_key_manager="CUSTOMER",
        )
        is None
    )


def test_ecr_customer_managed_kms_passes_for_dsse_customer_key():
    assert (
        check_ecr_customer_managed_kms(
            repository_name="prod/app",
            encryption_type="KMS_DSSE",
            kms_key="arn:aws:kms:us-east-1:123456789012:key/key-1",
            kms_key_manager="CUSTOMER",
        )
        is None
    )


def test_ecr_customer_managed_kms_fails_for_aes256():
    result = check_ecr_customer_managed_kms(
        repository_name="prod/app",
        encryption_type="AES256",
        kms_key=None,
        kms_key_manager=None,
    )

    assert result is not None


def test_ecr_customer_managed_kms_fails_for_aws_managed_key():
    result = check_ecr_customer_managed_kms(
        repository_name="prod/app",
        encryption_type="KMS",
        kms_key="arn:aws:kms:us-east-1:123456789012:key/aws-ecr",
        kms_key_manager="AWS",
    )

    assert result is not None
