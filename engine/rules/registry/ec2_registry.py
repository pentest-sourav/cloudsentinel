from engine.rules.aws.ec2.ebs_encryption import (
    build_ebs_encryption_finding,
    check_ebs_encryption,
)
from engine.rules.aws.ec2.imdsv1 import (
    build_imdsv1_finding,
    check_imdsv1,
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
            ["instance_id", "metadata_http_tokens"],
            check_imdsv1,
            build_imdsv1_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-004",
            "ebs_encryption",
            "ec2_ebs_volumes",
            "multiple",
            ["instance_id", "volume_id", "encrypted"],
            check_ebs_encryption,
            build_ebs_encryption_finding,
        ),
        RuleDefinition(
            "CS-AWS-EC2-005",
            "public_ebs_snapshot",
            "ec2_snapshots",
            "multiple",
            ["snapshot_id", "volume_id", "state", "public"],
            check_public_snapshot,
            build_public_snapshot_finding,
        ),
    ]
)
