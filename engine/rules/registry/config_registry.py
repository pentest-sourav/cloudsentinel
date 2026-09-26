from engine.rules.aws.config.controls import (
    build_config_account_enabled_finding,
    build_config_service_linked_role_finding,
    check_config_account_enabled,
    check_config_service_linked_role,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


CONFIG_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-CONFIG-001",
            name="config_recorder_enabled",
            data_source="config_account",
            collection_mode="single",
            check_arguments=[
                "recorder_count",
                "active_recorder_count",
                "recorder_names",
                "active_recorder_names",
            ],
            check=check_config_account_enabled,
            build_finding=(
                build_config_account_enabled_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-CONFIG-002",
            name="config_service_linked_role",
            data_source="config_recorders",
            collection_mode="multiple",
            check_arguments=[
                "name",
                "role_arn",
                "service_principal",
                "recording",
            ],
            check=check_config_service_linked_role,
            build_finding=(
                build_config_service_linked_role_finding
            ),
        ),
    ]
)
