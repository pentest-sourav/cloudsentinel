from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.rds.public_access import (
    build_public_rds_finding,
    check_public_rds,
)
from engine.rules.aws.rds.storage_encryption import (
    build_rds_storage_encryption_finding,
    check_rds_storage_encryption,
)
from engine.rules.aws.rds.backup_retention import (
    build_rds_backup_retention_finding,
    check_rds_backup_retention,
)
from engine.rules.aws.rds.multi_az import (
    build_rds_multi_az_finding,
    check_rds_multi_az,
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
        RuleDefinition(
            rule_id="CS-AWS-RDS-002",
            name="rds_storage_encryption",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "storage_encrypted",
            ],
            check=check_rds_storage_encryption,
            build_finding=build_rds_storage_encryption_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-RDS-003",
            name="rds_backup_retention",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "backup_retention_period",
            ],
            check=check_rds_backup_retention,
            build_finding=build_rds_backup_retention_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-RDS-004",
            name="rds_multi_az",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "multi_az",
            ],
            check=check_rds_multi_az,
            build_finding=build_rds_multi_az_finding,
        ),
    ]
)
