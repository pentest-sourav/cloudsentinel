from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

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

from engine.rules.aws.ec2.security_group_exposure import (
    build_security_group_exposure_finding,
    check_security_group_exposure,
)


EC2_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-EC2-001",
            name="security_group_exposure",
            data_source="ec2_security_group_rules",
            collection_mode="multiple",
            check_arguments=[
                "security_group_id",
                "rule",
            ],
            check=check_security_group_exposure,
            build_finding=build_security_group_exposure_finding,
        ),

        RuleDefinition(
            rule_id="CS-AWS-EC2-002",
            name="public_ec2_exposure",
            data_source="ec2_instances",
            collection_mode="multiple",
            check_arguments=[
                "instance_id",
                "public_ip",
            ],
            check=check_public_ec2_exposure,
            build_finding=build_public_ec2_finding,
        ),

        RuleDefinition(
            rule_id="CS-AWS-EC2-003",
            name="imdsv1_enabled",
            data_source="ec2_instances",
            collection_mode="multiple",
            check_arguments=[
                "instance_id",
                "metadata_http_tokens",
            ],
            check=check_imdsv1,
            build_finding=build_imdsv1_finding,
        ),

        RuleDefinition(
            rule_id="CS-AWS-EC2-004",
            name="ebs_encryption",
            data_source="ec2_ebs_volumes",
            collection_mode="multiple",
            check_arguments=[
                "instance_id",
                "volume_id",
                "encrypted",
            ],
            check=check_ebs_encryption,
            build_finding=build_ebs_encryption_finding,
        ),
    ]
)
