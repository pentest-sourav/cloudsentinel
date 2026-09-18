from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.rds.public_access import (
    build_public_rds_finding,
    check_public_rds,
)


RDS_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-RDS-001",
            name="public_rds",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "publicly_accessible",
            ],
            check=check_public_rds,
            build_finding=build_public_rds_finding,
        ),
    ]
)
