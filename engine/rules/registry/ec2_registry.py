from functools import partial

from engine.rules.aws.ec2.ebs_default_encryption import (
    build_ebs_default_encryption_finding,
    check_ebs_default_encryption,
)
from engine.rules.aws.ec2.ebs_encryption import (
    build_ebs_encryption_finding,
    check_ebs_encryption,
)
from engine.rules.aws.ec2.imdsv1 import (
    build_imdsv1_finding,
    check_imdsv1,
)
from engine.rules.aws.ec2.launch_template_ebs_encryption import (
    build_launch_template_ebs_encryption_finding,
    check_launch_template_ebs_encryption,
)
from engine.rules.aws.ec2.multiple_enis import (
    build_multiple_enis_finding,
    check_multiple_enis,
)
from engine.rules.aws.ec2.paravirtual import (
    build_paravirtual_finding,
    check_paravirtual,
)
from engine.rules.aws.ec2.public_exposure import (
    build_public_ec2_finding,
    check_public_ec2_exposure,
)
from engine.rules.aws.ec2.public_snapshot import (
    build_public_snapshot_finding,
    check_public_snapshot,
)
from engine.rules.aws.ec2.security_group_exposure import (
    build_security_group_exposure_finding,
    check_security_group_exposure,
)
from engine.rules.aws.ec2.snapshot_block_public_access import (
    build_snapshot_block_public_access_finding,
    check_snapshot_block_public_access,
)
from engine.rules.aws.ec2.stopped_instance import (
    build_stopped_instance_finding,
    check_stopped_instance,
)
from engine.rules.aws.ec2.unused_elastic_ip import (
    build_unused_elastic_ip_finding,
    check_unused_elastic_ip,
)
from engine.rules.aws.ec2.tagging import (
    build_ec2_tagging_finding,
    check_ec2_tagging,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


def _tagging_check(
    rule_id: str,
    title: str,
):
    return partial(
        check_ec2_tagging,
        rule_id=rule_id,
        title=title,
    )


EC2_RULES = RuleRegistry(
    [
        RuleDefinition(
            "CS-AWS-EC2-001",
            "security_group_exposure",
            "ec2_security_group_rules",
            "multiple",
            ["security_group_id", "rule"],
            check_security_group_exposure,
            build_security_group_exposure_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-002",
            "public_ec2_exposure",
            "ec2_instances",
            "multiple",
            ["instance_id", "public_ip"],
            check_public_ec2_exposure,
            build_public_ec2_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-003",
            "imdsv1_enabled",
            "ec2_instances",
            "multiple",
            [
                "instance_id",
                "metadata_http_tokens",
            ],
            check_imdsv1,
            build_imdsv1_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-004",
            "ebs_encryption",
            "ec2_ebs_volumes",
            "multiple",
            [
                "instance_id",
                "volume_id",
                "encrypted",
            ],
            check_ebs_encryption,
            build_ebs_encryption_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-005",
            "public_ebs_snapshot",
            "ec2_snapshots",
            "multiple",
            [
                "snapshot_id",
                "volume_id",
                "state",
                "public",
            ],
            check_public_snapshot,
            build_public_snapshot_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-006",
            "ebs_default_encryption",
            "ec2_ebs_default_encryption",
            "multiple",
            ["ebs_encryption_by_default"],
            check_ebs_default_encryption,
            build_ebs_default_encryption_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-007",
            "unused_elastic_ip",
            "ec2_elastic_ips",
            "multiple",
            [
                "allocation_id",
                "public_ip",
                "instance_id",
                "network_interface_id",
                "associated",
            ],
            check_unused_elastic_ip,
            build_unused_elastic_ip_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-008",
            "multiple_enis",
            "ec2_extended_instances",
            "multiple",
            [
                "instance_id",
                "network_interface_count",
            ],
            check_multiple_enis,
            build_multiple_enis_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-009",
            "paravirtual_instance",
            "ec2_extended_instances",
            "multiple",
            [
                "instance_id",
                "virtualization_type",
            ],
            check_paravirtual,
            build_paravirtual_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-010",
            "stopped_instance",
            "ec2_extended_instances",
            "multiple",
            [
                "instance_id",
                "instance_state",
                "launch_time",
                "state_transition_reason",
            ],
            check_stopped_instance,
            build_stopped_instance_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-181",
            "launch_template_ebs_encryption",
            "ec2_launch_template_ebs_encryption",
            "multiple",
            [
                "launch_template_id",
                "launch_template_name",
                "version_number",
                "device_name",
                "encrypted",
            ],
            check_launch_template_ebs_encryption,
            build_launch_template_ebs_encryption_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-182",
            "snapshot_block_public_access",
            "ec2_snapshot_block_public_access",
            "multiple",
            [
                "state",
                "managed_by",
            ],
            check_snapshot_block_public_access,
            build_snapshot_block_public_access_finding,
        ),


        RuleDefinition(
            "CS-AWS-EC2-035",
            "network_interface_tagging",
            "ec2_network_interface_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-035", "network_interface_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-037",
            "elastic_ip_tagging",
            "ec2_elastic_ip_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-037", "elastic_ip_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-038",
            "instance_tagging",
            "ec2_instance_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-038", "instance_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-039",
            "internet_gateway_tagging",
            "ec2_internet_gateway_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-039", "internet_gateway_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-040",
            "nat_gateway_tagging",
            "ec2_nat_gateway_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-040", "nat_gateway_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-041",
            "network_acl_tagging",
            "ec2_network_acl_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-041", "network_acl_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-042",
            "route_table_tagging",
            "ec2_route_table_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-042", "route_table_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-043",
            "security_group_tagging",
            "ec2_security_group_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-043", "security_group_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-044",
            "subnet_tagging",
            "ec2_subnet_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-044", "subnet_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-045",
            "volume_tagging",
            "ec2_volume_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-045", "volume_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-046",
            "vpc_tagging",
            "ec2_vpc_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-046", "vpc_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-048",
            "vpc_flow_log_tagging",
            "ec2_flow_log_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-048", "vpc_flow_log_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-049",
            "vpc_peering_connection_tagging",
            "ec2_vpc_peering_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-049", "vpc_peering_connection_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-050",
            "vpn_gateway_tagging",
            "ec2_vpn_gateway_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-050", "vpn_gateway_tagging"),
            build_ec2_tagging_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-052",
            "transit_gateway_tagging",
            "ec2_transit_gateway_tagging",
            "multiple",
            [
                "resource_id",
                "resource_type",
                "tags",
            ],
            _tagging_check("CS-AWS-EC2-052", "transit_gateway_tagging"),
            build_ec2_tagging_finding,
        ),
    ]
)
