import pytest

from engine.findings.model import Severity
from engine.rules.aws.vpc.client_vpn_logging import (
    build_client_vpn_logging_finding,
    check_client_vpn_logging,
)
from engine.rules.aws.vpc.eni_source_destination_check import (
    build_eni_source_destination_check_finding,
    check_eni_source_destination_check,
)
from engine.rules.aws.vpc.spot_fleet_ebs_encryption import (
    build_spot_fleet_ebs_encryption_finding,
    check_spot_fleet_ebs_encryption,
)
from engine.rules.aws.vpc.vpn_ikev2 import (
    build_vpn_ikev2_finding,
    check_vpn_ikev2,
)
from engine.rules.aws.vpc.vpn_logging import (
    build_vpn_logging_finding,
    check_vpn_logging,
)


def test_vpc_016_compliant_and_noncompliant():
    assert check_client_vpn_logging(
        "cvpn-1",
        "vpc-1",
        True,
    ) is None

    result = check_client_vpn_logging(
        "cvpn-2",
        "vpc-2",
        False,
    )

    assert result is not None

    finding = build_client_vpn_logging_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-016"
    assert finding.severity == Severity.LOW
    assert finding.resource_id == "cvpn-2"


@pytest.mark.parametrize(
    ("tunnel_1", "tunnel_2"),
    [
        (False, True),
        (True, False),
        (False, False),
    ],
)
def test_vpc_017_requires_logging_on_both_tunnels(
    tunnel_1,
    tunnel_2,
):
    result = check_vpn_logging(
        "vpn-1",
        tunnel_1,
        tunnel_2,
    )

    assert result is not None

    finding = build_vpn_logging_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-017"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["tunnel_1_logging_enabled"] is tunnel_1
    assert finding.evidence["tunnel_2_logging_enabled"] is tunnel_2


def test_vpc_017_accepts_both_tunnels_logged():
    assert check_vpn_logging(
        "vpn-1",
        True,
        True,
    ) is None


def test_vpc_018_flags_unencrypted_ebs_volumes():
    assert check_spot_fleet_ebs_encryption(
        "sfr-1",
        False,
        0,
        0,
    ) is None

    result = check_spot_fleet_ebs_encryption(
        "sfr-2",
        True,
        3,
        1,
    )

    assert result is not None

    finding = build_spot_fleet_ebs_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-018"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["ebs_volume_count"] == 3
    assert finding.evidence["unencrypted_volume_count"] == 1


def test_vpc_018_accepts_all_explicitly_encrypted_ebs_volumes():
    assert check_spot_fleet_ebs_encryption(
        "sfr-1",
        True,
        2,
        0,
    ) is None


def test_vpc_019_only_evaluates_managed_interface_types():
    assert check_eni_source_destination_check(
        "eni-ignored",
        "nat_gateway",
        False,
        "vpc-1",
        "subnet-1",
    ) is None

    result = check_eni_source_destination_check(
        "eni-1",
        "INTERFACE",
        False,
        "vpc-1",
        "subnet-1",
    )

    assert result is not None
    assert result.interface_type == "interface"

    finding = build_eni_source_destination_check_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-019"
    assert finding.severity == Severity.MEDIUM


def test_vpc_019_accepts_enabled_source_destination_check():
    assert check_eni_source_destination_check(
        "eni-1",
        "interface",
        True,
        "vpc-1",
        "subnet-1",
    ) is None


@pytest.mark.parametrize(
    "versions",
    [
        ["ikev1"],
        ["ikev1", "ikev2"],
        [],
    ],
)
def test_vpc_020_requires_ikev2_only(versions):
    result = check_vpn_ikev2(
        "vpn-1",
        versions,
        ["ikev2"],
    )

    assert result is not None

    finding = build_vpn_ikev2_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-020"
    assert finding.severity == Severity.MEDIUM


def test_vpc_020_accepts_ikev2_only_on_both_tunnels():
    assert check_vpn_ikev2(
        "vpn-1",
        ["IKEv2"],
        [" ikev2 "],
    ) is None
