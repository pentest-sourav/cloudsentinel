from engine.rules.aws.guardduty.protection import (
    build_gd001,
    build_gd002,
    build_gd003,
    build_gd004,
    build_gd005,
    build_gd006,
    build_gd007,
    build_gd008,
    build_gd009,
    build_gd010,
    check_detector_enabled,
    check_ec2_runtime_monitoring,
    check_ecs_runtime_monitoring,
    check_eks_runtime_monitoring,
    check_feature,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


def check_eks_audit_logs(
    resource_id,
    features,
):
    return check_feature(
        resource_id,
        features,
        "EKS_AUDIT_LOGS",
        "GuardDuty EKS Audit Log Monitoring",
    )


def check_lambda_protection(
    resource_id,
    features,
):
    return check_feature(
        resource_id,
        features,
        "LAMBDA_NETWORK_LOGS",
        "GuardDuty Lambda Protection",
    )


def check_malware_protection(
    resource_id,
    features,
):
    return check_feature(
        resource_id,
        features,
        "EBS_MALWARE_PROTECTION",
        "GuardDuty Malware Protection for EC2",
    )


def check_rds_protection(
    resource_id,
    features,
):
    return check_feature(
        resource_id,
        features,
        "RDS_LOGIN_EVENTS",
        "GuardDuty RDS Protection",
    )


def check_s3_protection(
    resource_id,
    features,
):
    return check_feature(
        resource_id,
        features,
        "S3_DATA_EVENTS",
        "GuardDuty S3 Protection",
    )


def check_runtime_monitoring(
    resource_id,
    features,
):
    return check_feature(
        resource_id,
        features,
        "RUNTIME_MONITORING",
        "GuardDuty Runtime Monitoring",
    )


GUARDDUTY_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-GD-001",
            name="GuardDuty should be enabled",
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "status",
            ],
            check=check_detector_enabled,
            build_finding=build_gd001,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-005",
            name=(
                "GuardDuty EKS Audit Log Monitoring "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_eks_audit_logs,
            build_finding=build_gd002,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-006",
            name=(
                "GuardDuty Lambda Protection "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_lambda_protection,
            build_finding=build_gd003,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-007",
            name=(
                "GuardDuty EKS Runtime Monitoring "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_eks_runtime_monitoring,
            build_finding=build_gd004,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-008",
            name=(
                "GuardDuty Malware Protection for EC2 "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_malware_protection,
            build_finding=build_gd005,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-009",
            name=(
                "GuardDuty RDS Protection "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_rds_protection,
            build_finding=build_gd006,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-010",
            name=(
                "GuardDuty S3 Protection "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_s3_protection,
            build_finding=build_gd007,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-011",
            name=(
                "GuardDuty Runtime Monitoring "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_runtime_monitoring,
            build_finding=build_gd008,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-012",
            name=(
                "GuardDuty ECS Runtime Monitoring "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_ecs_runtime_monitoring,
            build_finding=build_gd009,
        ),
        RuleDefinition(
            rule_id="CS-AWS-GD-013",
            name=(
                "GuardDuty EC2 Runtime Monitoring "
                "should be enabled"
            ),
            data_source="guardduty_detectors",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "features",
            ],
            check=check_ec2_runtime_monitoring,
            build_finding=build_gd010,
        ),
    ]
)
