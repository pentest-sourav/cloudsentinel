from engine.rules.aws.ses.protection import (
    build_ses_configuration_set_tagging_finding,
    build_ses_contact_list_tagging_finding,
    build_ses_tls_finding,
    check_ses_tagging,
    check_ses_tls,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


SES_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SES-001",
            name="SES contact lists should be tagged",
            data_source="ses_contact_lists",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_type",
                "tags",
            ],
            check=check_ses_tagging,
            build_finding=(
                build_ses_contact_list_tagging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-SES-002",
            name="SES configuration sets should be tagged",
            data_source="ses_configuration_sets",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_type",
                "tags",
            ],
            check=check_ses_tagging,
            build_finding=(
                build_ses_configuration_set_tagging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-SES-003",
            name=(
                "SES configuration sets should have TLS "
                "enabled for sending emails"
            ),
            data_source="ses_configuration_sets",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "tls_policy",
            ],
            check=check_ses_tls,
            build_finding=build_ses_tls_finding,
        ),
    ]
)
