from engine.rules.aws.inspector.protection import (
    build_inspector_001,
    build_inspector_002,
    build_inspector_003,
    build_inspector_004,
    check_ec2_scanning,
    check_ecr_scanning,
    check_lambda_code_scanning,
    check_lambda_scanning,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


INSPECTOR_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-INSPECTOR-001",
            name=(
                "Amazon Inspector EC2 scanning "
                "should be enabled"
            ),
            data_source="inspector_account",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "ec2_status",
            ],
            check=check_ec2_scanning,
            build_finding=build_inspector_001,
        ),
        RuleDefinition(
            rule_id="CS-AWS-INSPECTOR-002",
            name=(
                "Amazon Inspector ECR scanning "
                "should be enabled"
            ),
            data_source="inspector_account",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "ecr_status",
            ],
            check=check_ecr_scanning,
            build_finding=build_inspector_002,
        ),
        RuleDefinition(
            rule_id="CS-AWS-INSPECTOR-003",
            name=(
                "Amazon Inspector Lambda code scanning "
                "should be enabled"
            ),
            data_source="inspector_account",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "lambda_code_status",
            ],
            check=check_lambda_code_scanning,
            build_finding=build_inspector_003,
        ),
        RuleDefinition(
            rule_id="CS-AWS-INSPECTOR-004",
            name=(
                "Amazon Inspector Lambda standard scanning "
                "should be enabled"
            ),
            data_source="inspector_account",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "lambda_status",
            ],
            check=check_lambda_scanning,
            build_finding=build_inspector_004,
        ),
    ]
)
