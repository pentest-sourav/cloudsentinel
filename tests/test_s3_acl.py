from engine.findings.model import Severity
from engine.rules.aws.s3.acl import (
    build_s3_acl_finding,
    check_s3_acl,
)


ALL_USERS_URI = (
    "http://acs.amazonaws.com/groups/global/AllUsers"
)

AUTHENTICATED_USERS_URI = (
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)


def test_all_users_acl_generates_high_finding():
    acl = {
        "Owner": {
            "ID": "owner-id",
        },
        "Grants": [
            {
                "Grantee": {
                    "URI": ALL_USERS_URI,
                    "Type": "Group",
                },
                "Permission": "READ",
            }
        ],
    }

    result = check_s3_acl(
        bucket_name="public-acl-bucket",
        acl=acl,
    )

    assert result.broad_access is True
    assert result.bucket_name == "public-acl-bucket"
    assert len(result.public_grants) == 1

    finding = build_s3_acl_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-004"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "public-acl-bucket"
    assert finding.evidence["broad_access"] is True
    assert len(finding.evidence["public_grants"]) == 1


def test_authenticated_users_acl_generates_high_finding():
    acl = {
        "Owner": {
            "ID": "owner-id",
        },
        "Grants": [
            {
                "Grantee": {
                    "URI": AUTHENTICATED_USERS_URI,
                    "Type": "Group",
                },
                "Permission": "READ",
            }
        ],
    }

    result = check_s3_acl(
        bucket_name="broad-access-bucket",
        acl=acl,
    )

    assert result.broad_access is True

    finding = build_s3_acl_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-004"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "broad-access-bucket"


def test_owner_only_acl_has_no_finding():
    acl = {
        "Owner": {
            "ID": "owner-id",
        },
        "Grants": [
            {
                "Grantee": {
                    "ID": "owner-id",
                    "Type": "CanonicalUser",
                },
                "Permission": "FULL_CONTROL",
            }
        ],
    }

    result = check_s3_acl(
        bucket_name="secure-bucket",
        acl=acl,
    )

    assert result.broad_access is False
    assert result.public_grants == []

    finding = build_s3_acl_finding(result)

    assert finding is None


def test_empty_acl_has_no_finding():
    acl = {}

    result = check_s3_acl(
        bucket_name="empty-acl-bucket",
        acl=acl,
    )

    assert result.broad_access is False
    assert result.public_grants == []

    finding = build_s3_acl_finding(result)

    assert finding is None
