from engine.rules.aws.elasticbeanstalk.protection import (
    build_cloudwatch_log_streaming_finding,
    build_enhanced_health_reporting_finding,
    build_managed_platform_updates_finding,
    check_cloudwatch_log_streaming,
    check_enhanced_health_reporting,
    check_managed_platform_updates,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


ELASTICBEANSTALK_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-ELASTICBEANSTALK-001",
            name="elasticbeanstalk_enhanced_health_reporting",
            data_source="elasticbeanstalk_environments",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "enhanced_health_reporting",
            ],
            check=check_enhanced_health_reporting,
            build_finding=(
                build_enhanced_health_reporting_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ELASTICBEANSTALK-002",
            name="elasticbeanstalk_managed_platform_updates",
            data_source="elasticbeanstalk_environments",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "managed_actions_enabled",
                "managed_update_level",
            ],
            check=check_managed_platform_updates,
            build_finding=(
                build_managed_platform_updates_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ELASTICBEANSTALK-003",
            name="elasticbeanstalk_cloudwatch_log_streaming",
            data_source="elasticbeanstalk_environments",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "stream_logs",
            ],
            check=check_cloudwatch_log_streaming,
            build_finding=(
                build_cloudwatch_log_streaming_finding
            ),
        ),
    ]
)
