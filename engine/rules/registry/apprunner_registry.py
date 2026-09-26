from engine.rules.aws.apprunner.controls import (
    build_apprunner_service_tags_finding,
    build_apprunner_vpc_connector_tags_finding,
    check_apprunner_service_tags,
    check_apprunner_vpc_connector_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


APPRUNNER_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-APPRUNNER-001",
            name="apprunner_service_tags",
            data_source="apprunner_services",
            collection_mode="multiple",
            check_arguments=[
                "service_name",
                "service_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_apprunner_service_tags,
            build_finding=build_apprunner_service_tags_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-APPRUNNER-002",
            name="apprunner_vpc_connector_tags",
            data_source="apprunner_vpc_connectors",
            collection_mode="multiple",
            check_arguments=[
                "vpc_connector_name",
                "vpc_connector_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_apprunner_vpc_connector_tags,
            build_finding=build_apprunner_vpc_connector_tags_finding,
        ),
    ]
)
