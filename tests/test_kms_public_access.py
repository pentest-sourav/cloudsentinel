from engine.findings.model import Severity
from engine.rules.aws.kms.public_access import (
    build_kms_public_access_finding,
    check_kms_public_access,
)


def test_public_kms_policy_fails():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
    }

    result = check_kms_public_access(
        "key-1",
        policy,
    )

    assert result is not None
    assert result.actions == ("kms:Decrypt",)

    finding = build_kms_public_access_finding(result)

    assert finding.rule_id == "CS-AWS-KMS-003"
    assert finding.severity == Severity.CRITICAL


def test_public_policy_with_condition_is_not_flagged():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": "o-example"
                        }
                    },
                }
            ],
        }
    }

    assert check_kms_public_access("key-1", policy) is None


def test_specific_principal_is_not_public():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/AppRole"
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                }
            ],
        }
    }

    assert check_kms_public_access("key-1", policy) is None


def test_non_kms_action_is_ignored():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
    }

    assert check_kms_public_access("key-1", policy) is None
