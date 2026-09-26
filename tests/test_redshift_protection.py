from engine.rules.aws.redshift.protection import (
    check_redshift_public_access,
    check_redshift_require_ssl,
    check_redshift_backup_retention,
    check_redshift_audit_logging,
    check_redshift_allow_version_upgrade,
    check_redshift_enhanced_vpc_routing,
    check_redshift_default_admin,
    check_redshift_encryption,
    check_redshift_unrestricted_port,
    check_redshift_multi_az,
)
from engine.rules.registry.redshift_registry import REDSHIFT_RULES


def test_redshift_rule_registry_contains_ten_rules():
    assert len(REDSHIFT_RULES) == 10

    assert [
        rule.rule_id for rule in REDSHIFT_RULES
    ] == [
        "CS-AWS-REDSHIFT-001",
        "CS-AWS-REDSHIFT-002",
        "CS-AWS-REDSHIFT-003",
        "CS-AWS-REDSHIFT-004",
        "CS-AWS-REDSHIFT-005",
        "CS-AWS-REDSHIFT-006",
        "CS-AWS-REDSHIFT-007",
        "CS-AWS-REDSHIFT-008",
        "CS-AWS-REDSHIFT-009",
        "CS-AWS-REDSHIFT-010",
    ]


def test_public_access_only_flags_true():
    assert check_redshift_public_access("cluster", True) is not None
    assert check_redshift_public_access("cluster", False) is None
    assert check_redshift_public_access("cluster", None) is None


def test_require_ssl_only_flags_non_true_value():
    assert check_redshift_require_ssl("cluster", "true") is None
    assert check_redshift_require_ssl("cluster", "false") is not None
    assert check_redshift_require_ssl("cluster", None) is None


def test_backup_retention_uses_security_hub_default_of_seven_days():
    assert check_redshift_backup_retention("cluster", 7) is None
    assert check_redshift_backup_retention("cluster", 8) is None
    assert check_redshift_backup_retention("cluster", 6) is not None
    assert check_redshift_backup_retention("cluster", 0) is not None
    assert check_redshift_backup_retention("cluster", None) is None


def test_audit_logging_only_flags_explicit_false():
    assert check_redshift_audit_logging("cluster", True) is None
    assert check_redshift_audit_logging("cluster", False) is not None
    assert check_redshift_audit_logging("cluster", None) is None


def test_version_upgrade_only_flags_false():
    assert check_redshift_allow_version_upgrade("cluster", True) is None
    assert check_redshift_allow_version_upgrade("cluster", False) is not None
    assert check_redshift_allow_version_upgrade("cluster", None) is None


def test_enhanced_vpc_routing_only_flags_false():
    assert check_redshift_enhanced_vpc_routing("cluster", True) is None
    assert check_redshift_enhanced_vpc_routing("cluster", False) is not None
    assert check_redshift_enhanced_vpc_routing("cluster", None) is None


def test_default_admin_only_flags_awsuser():
    assert check_redshift_default_admin("cluster", "awsuser") is not None
    assert check_redshift_default_admin("cluster", "cloudadmin") is None
    assert check_redshift_default_admin("cluster", None) is None


def test_encryption_only_flags_false():
    assert check_redshift_encryption("cluster", True) is None
    assert check_redshift_encryption("cluster", False) is not None
    assert check_redshift_encryption("cluster", None) is None


def test_unrestricted_port_flags_ipv4_or_ipv6_zero_route():
    restricted = [
        {
            "security_group_id": "sg-1",
            "ipv4_ranges": ["10.0.0.0/16"],
            "ipv6_ranges": [],
        }
    ]

    assert (
        check_redshift_unrestricted_port(
            "cluster",
            5439,
            restricted,
        )
        is None
    )

    unrestricted_ipv4 = [
        {
            "security_group_id": "sg-1",
            "ipv4_ranges": ["0.0.0.0/0"],
            "ipv6_ranges": [],
        }
    ]

    assert (
        check_redshift_unrestricted_port(
            "cluster",
            5439,
            unrestricted_ipv4,
        )
        is not None
    )

    unrestricted_ipv6 = [
        {
            "security_group_id": "sg-1",
            "ipv4_ranges": [],
            "ipv6_ranges": ["::/0"],
        }
    ]

    assert (
        check_redshift_unrestricted_port(
            "cluster",
            5439,
            unrestricted_ipv6,
        )
        is not None
    )


def test_multi_az_only_flags_false():
    assert check_redshift_multi_az("cluster", True) is None
    assert check_redshift_multi_az("cluster", False) is not None
    assert check_redshift_multi_az("cluster", None) is None
