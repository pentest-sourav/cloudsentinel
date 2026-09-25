from engine.rules.aws.acm.expiration import (
    build_acm_expiration_finding,
    check_acm_expiration,
)
from engine.rules.aws.acm.rsa_key_length import (
    build_acm_rsa_key_length_finding,
    check_acm_rsa_key_length,
)
from engine.rules.aws.acm.tagging import (
    build_acm_tagging_finding,
    check_acm_tagging,
)

from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


ACM_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-ACM-001",
            name=(
                "ACM certificates should be renewed "
                "within the specified time period"
            ),
            data_source="acm_certificates",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "not_after",
            ],
            check=check_acm_expiration,
            build_finding=(
                build_acm_expiration_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ACM-002",
            name=(
                "ACM RSA certificates should use "
                "a key length of at least 2048 bits"
            ),
            data_source="acm_certificates",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "key_algorithm",
            ],
            check=check_acm_rsa_key_length,
            build_finding=(
                build_acm_rsa_key_length_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ACM-003",
            name="ACM certificates should be tagged",
            data_source="acm_certificates",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "resource_arn",
                "tags",
            ],
            check=check_acm_tagging,
            build_finding=(
                build_acm_tagging_finding
            ),
        ),
    ]
)
