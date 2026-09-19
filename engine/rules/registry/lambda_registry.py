from engine.rules.aws.lambda_rules.public_function_url import (
    build_public_lambda_function_url_finding,
    check_public_lambda_function_url,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


LAMBDA_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-001",
            name="public_lambda_function_url",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "function_url",
                "url_auth_type",
            ],
            check=check_public_lambda_function_url,
            build_finding=build_public_lambda_function_url_finding,
        ),
    ]
)
