from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.rds.auto_minor_version_upgrade import (
    build_rds_auto_minor_version_upgrade_finding,
    check_rds_auto_minor_version_upgrade,
)
from engine.rules.aws.rds.backup_retention import (
    build_rds_backup_retention_finding,
    check_rds_backup_retention,
)
from engine.rules.aws.rds.cloudwatch_logs_export import (
    build_rds_cloudwatch_logs_export_finding,
    check_rds_cloudwatch_logs_export,
)
from engine.rules.aws.rds.deletion_protection import (
    build_rds_deletion_protection_finding,
    check_rds_deletion_protection,
)
from engine.rules.aws.rds.enhanced_monitoring import (
    build_rds_enhanced_monitoring_finding,
    check_rds_enhanced_monitoring,
)
from engine.rules.aws.rds.iam_database_authentication import (
    build_rds_iam_database_authentication_finding,
    check_rds_iam_database_authentication,
)
from engine.rules.aws.rds.multi_az import (
    build_rds_multi_az_finding,
    check_rds_multi_az,
)
from engine.rules.aws.rds.public_access import (
    build_public_rds_finding,
    check_public_rds,
)
from engine.rules.aws.rds.storage_encryption import (
    build_rds_storage_encryption_finding,
    check_rds_storage_encryption,
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
        RuleDefinition(
            rule_id="CS-AWS-RDS-005",
            name="rds_deletion_protection",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "deletion_protection",
            ],
            check=check_rds_deletion_protection,
            build_finding=build_rds_deletion_protection_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-RDS-006",
            name="rds_auto_minor_version_upgrade",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "engine",
                "auto_minor_version_upgrade",
            ],
            check=check_rds_auto_minor_version_upgrade,
            build_finding=build_rds_auto_minor_version_upgrade_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-RDS-007",
            name="rds_iam_database_authentication",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "engine",
                "iam_database_authentication_enabled",
            ],
            check=check_rds_iam_database_authentication,
            build_finding=(
                build_rds_iam_database_authentication_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-RDS-008",
            name="rds_cloudwatch_logs_export",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "engine",
                "enabled_cloudwatch_logs_exports",
            ],
            check=check_rds_cloudwatch_logs_export,
            build_finding=build_rds_cloudwatch_logs_export_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-RDS-009",
            name="rds_enhanced_monitoring",
            data_source="rds_instances",
            collection_mode="multiple",
            check_arguments=[
                "db_instance_id",
                "monitoring_interval",
            ],
            check=check_rds_enhanced_monitoring,
            build_finding=build_rds_enhanced_monitoring_finding,
        ),
    ]
)
