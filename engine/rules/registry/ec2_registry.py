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
from engine.rules.aws.ec2.stopped_instance import (
    build_stopped_instance_finding,
    check_stopped_instance,
)
from engine.rules.aws.ec2.unused_elastic_ip import (
    build_unused_elastic_ip_finding,
    check_unused_elastic_ip,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


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
    ]
)
