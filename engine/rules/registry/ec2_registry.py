from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

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
    ]
)
