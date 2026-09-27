from unittest.mock import MagicMock

from engine.rules.aws.vpc.nacl_remote_admin import (
    build_nacl_remote_admin_finding,
    check_nacl_remote_admin,
)
from engine.rules.aws.vpc.required_endpoints import (
    build_ecr_api_endpoint_finding,
    build_ecr_dkr_endpoint_finding,
    build_ssm_contacts_endpoint_finding,
    build_ssm_endpoint_finding,
    build_ssm_incidents_endpoint_finding,
    check_required_endpoint,
)
from engine.rules.aws.vpc.subnet_public_ip import (
    build_subnet_public_ip_finding,
    check_subnet_public_ip,
)
from engine.rules.aws.vpc.unused_network_acl import (
    build_unused_network_acl_finding,
    check_unused_network_acl,
)
from scanner.aws.collectors.vpc import VPCDataCollector
from scanner.aws.services.vpc import VPCService


def test_subnet_public_ip_flags_enabled():
    result = check_subnet_public_ip(
        "subnet-1",
        "vpc-1",
        True,
    )

    assert result is not None
    assert result.subnet_id == "subnet-1"


def test_subnet_public_ip_accepts_disabled():
    assert (
        check_subnet_public_ip(
            "subnet-1",
            "vpc-1",
            False,
        )
        is None
    )


def test_subnet_public_ip_finding():
    result = check_subnet_public_ip(
        "subnet-1",
        "vpc-1",
        True,
    )

    finding = build_subnet_public_ip_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-008"
    assert finding.severity.value == "medium"
    assert finding.resource_id == "subnet-1"


def test_unused_network_acl_flags_unassociated_non_default():
    result = check_unused_network_acl(
        "acl-1",
        "vpc-1",
        0,
        False,
    )

    assert result is not None


def test_unused_network_acl_accepts_associated_acl():
    assert (
        check_unused_network_acl(
            "acl-1",
            "vpc-1",
            1,
            False,
        )
        is None
    )


def test_unused_network_acl_accepts_default_acl():
    assert (
        check_unused_network_acl(
            "acl-1",
            "vpc-1",
            0,
            True,
        )
        is None
    )


def test_unused_network_acl_finding():
    result = check_unused_network_acl(
        "acl-1",
        "vpc-1",
        0,
        False,
    )

    finding = build_unused_network_acl_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-009"
    assert finding.severity.value == "low"


def test_nacl_remote_admin_flags_tcp_22():
    result = check_nacl_remote_admin(
        "acl-1",
        "vpc-1",
        100,
        False,
        "6",
        "0.0.0.0/0",
        None,
        22,
        22,
    )

    assert result is not None


def test_nacl_remote_admin_flags_tcp_3389():
    result = check_nacl_remote_admin(
        "acl-1",
        "vpc-1",
        100,
        False,
        "tcp",
        None,
        "::/0",
        3389,
        3389,
    )

    assert result is not None


def test_nacl_remote_admin_flags_all_protocol():
    result = check_nacl_remote_admin(
        "acl-1",
        "vpc-1",
        100,
        False,
        "-1",
        "0.0.0.0/0",
        None,
        None,
        None,
    )

    assert result is not None


def test_nacl_remote_admin_ignores_egress():
    assert (
        check_nacl_remote_admin(
            "acl-1",
            "vpc-1",
            100,
            True,
            "tcp",
            "0.0.0.0/0",
            None,
            22,
            22,
        )
        is None
    )


def test_nacl_remote_admin_ignores_private_source():
    assert (
        check_nacl_remote_admin(
            "acl-1",
            "vpc-1",
            100,
            False,
            "tcp",
            "10.0.0.0/8",
            None,
            22,
            22,
        )
        is None
    )


def test_nacl_remote_admin_finding():
    result = check_nacl_remote_admin(
        "acl-1",
        "vpc-1",
        100,
        False,
        "tcp",
        "0.0.0.0/0",
        None,
        22,
        22,
    )

    finding = build_nacl_remote_admin_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-010"
    assert finding.severity.value == "medium"


def test_required_endpoint_flags_missing():
    result = check_required_endpoint(
        "vpc-1",
        "us-east-1",
        "com.amazonaws.us-east-1.ecr.api",
        "interface",
        False,
    )

    assert result is not None


def test_required_endpoint_accepts_present():
    assert (
        check_required_endpoint(
            "vpc-1",
            "us-east-1",
            "com.amazonaws.us-east-1.ecr.api",
            "interface",
            True,
        )
        is None
    )


def test_required_endpoint_builders():
    result = check_required_endpoint(
        "vpc-1",
        "us-east-1",
        "com.amazonaws.us-east-1.ecr.api",
        "interface",
        False,
    )

    findings = [
        build_ecr_api_endpoint_finding(result),
        build_ecr_dkr_endpoint_finding(result),
        build_ssm_endpoint_finding(result),
        build_ssm_contacts_endpoint_finding(result),
        build_ssm_incidents_endpoint_finding(result),
    ]

    assert [finding.rule_id for finding in findings] == [
        "CS-AWS-VPC-011",
        "CS-AWS-VPC-012",
        "CS-AWS-VPC-013",
        "CS-AWS-VPC-014",
        "CS-AWS-VPC-015",
    ]


def test_vpc_collector_subnet_coverage():
    service = MagicMock()
    service.describe_subnets.return_value = [
        {
            "SubnetId": "subnet-1",
            "VpcId": "vpc-1",
            "MapPublicIpOnLaunch": True,
        },
        {
            "SubnetId": "subnet-2",
            "VpcId": "vpc-1",
            "MapPublicIpOnLaunch": False,
        },
    ]

    collector = VPCDataCollector(service)

    assert collector.collect_subnet_public_ip_coverage() == [
        {
            "subnet_id": "subnet-1",
            "vpc_id": "vpc-1",
            "map_public_ip_on_launch": True,
        },
        {
            "subnet_id": "subnet-2",
            "vpc_id": "vpc-1",
            "map_public_ip_on_launch": False,
        },
    ]


def test_vpc_collector_unused_nacl_coverage():
    service = MagicMock()
    service.describe_network_acls.return_value = [
        {
            "NetworkAclId": "acl-1",
            "VpcId": "vpc-1",
            "IsDefault": False,
            "Associations": [],
        },
        {
            "NetworkAclId": "acl-2",
            "VpcId": "vpc-1",
            "IsDefault": True,
            "Associations": [{"NetworkAclAssociationId": "a-1"}],
        },
    ]

    collector = VPCDataCollector(service)

    assert collector.collect_unused_network_acl_coverage() == [
        {
            "network_acl_id": "acl-1",
            "vpc_id": "vpc-1",
            "association_count": 0,
            "is_default": False,
        },
        {
            "network_acl_id": "acl-2",
            "vpc_id": "vpc-1",
            "association_count": 1,
            "is_default": True,
        },
    ]


def test_vpc_collector_required_endpoint_coverage():
    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"
    service.describe_vpcs.return_value = [
        {"VpcId": "vpc-1"},
        {"VpcId": "vpc-2"},
    ]
    service.describe_vpc_endpoints.return_value = [
        {
            "VpcId": "vpc-1",
            "ServiceName": "com.amazonaws.us-east-1.ecr.api",
            "VpcEndpointType": "Interface",
        }
    ]

    collector = VPCDataCollector(service)

    assert collector.collect_required_endpoint_coverage(
        "com.amazonaws.us-east-1.ecr.api"
    ) == [
        {
            "vpc_id": "vpc-1",
            "region": "us-east-1",
            "service_name": "com.amazonaws.us-east-1.ecr.api",
            "endpoint_type": "interface",
            "endpoint_enabled": True,
        },
        {
            "vpc_id": "vpc-2",
            "region": "us-east-1",
            "service_name": "com.amazonaws.us-east-1.ecr.api",
            "endpoint_type": "interface",
            "endpoint_enabled": False,
        },
    ]


def test_vpc_service_describes_subnets():
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Subnets": [
                {
                    "SubnetId": "subnet-1",
                    "VpcId": "vpc-1",
                    "MapPublicIpOnLaunch": True,
                }
            ]
        }
    ]
    client.get_paginator.return_value = paginator

    service = VPCService.__new__(VPCService)
    service.ec2_client = client

    assert service.describe_subnets() == [
        {
            "SubnetId": "subnet-1",
            "VpcId": "vpc-1",
            "MapPublicIpOnLaunch": True,
        }
    ]
