from engine.findings.model import Severity
from engine.rules.aws.kms.overly_permissive_policy import (
    build_kms_overly_permissive_policy_finding,
    check_kms_overly_permissive_policy,
)


def test_kms_star_for_specific_principal_fails():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/AdminRole"
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    }

    result = check_kms_overly_permissive_policy("key-1", policy)

    assert result is not None
    assert result.actions == ("kms:*",)

    finding = build_kms_overly_permissive_policy_finding(result)

    assert finding.rule_id == "CS-AWS-KMS-004"
    assert finding.severity == Severity.HIGH


def test_sensitive_kms_action_fails():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/AdminRole"
                    },
                    "Action": "kms:ScheduleKeyDeletion",
                    "Resource": "*",
                }
            ],
        }
    }

    result = check_kms_overly_permissive_policy("key-1", policy)

    assert result is not None
    assert result.actions == ("kms:ScheduleKeyDeletion",)


def test_public_principal_is_left_to_public_access_rule():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    }

    assert check_kms_overly_permissive_policy("key-1", policy) is None


def test_root_principal_is_not_flagged():
    policy = {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    }

    assert check_kms_overly_permissive_policy("key-1", policy) is None


def test_normal_kms_usage_action_is_not_flagged():
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

    assert check_kms_overly_permissive_policy("key-1", policy) is None
