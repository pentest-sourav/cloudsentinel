from engine.rules.aws.lambda_rules.code_signing import (
    build_lambda_code_signing_finding,
    check_lambda_code_signing,
)
from engine.rules.aws.lambda_rules.not_in_vpc import (
    build_lambda_not_in_vpc_finding,
    check_lambda_not_in_vpc,
)
from engine.rules.aws.lambda_rules.public_function_url import (
    build_public_lambda_function_url_finding,
    check_public_lambda_function_url,
)
from engine.rules.aws.lambda_rules.public_resource_policy import (
    build_public_lambda_resource_policy_finding,
    check_public_lambda_resource_policy,
)
from engine.rules.aws.lambda_rules.supported_runtime import (
    build_unsupported_lambda_runtime_finding,
    check_unsupported_lambda_runtime,
)
from engine.rules.aws.lambda_rules.vpc_multi_az import (
    build_lambda_vpc_multi_az_finding,
    check_lambda_vpc_multi_az,
)
from engine.rules.aws.lambda_rules.xray_tracing import (
    build_lambda_xray_tracing_finding,
    check_lambda_xray_tracing,
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
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-002",
            name="public_lambda_resource_policy",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "function_policy",
            ],
            check=check_public_lambda_resource_policy,
            build_finding=build_public_lambda_resource_policy_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-003",
            name="unsupported_lambda_runtime",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "runtime",
                "package_type",
            ],
            check=check_unsupported_lambda_runtime,
            build_finding=build_unsupported_lambda_runtime_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-004",
            name="lambda_not_in_vpc",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "vpc_id",
                "subnet_ids",
            ],
            check=check_lambda_not_in_vpc,
            build_finding=build_lambda_not_in_vpc_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-005",
            name="lambda_vpc_multi_az",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "vpc_id",
                "subnet_ids",
                "subnet_availability_zones",
            ],
            check=check_lambda_vpc_multi_az,
            build_finding=build_lambda_vpc_multi_az_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-006",
            name="lambda_xray_active_tracing",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "tracing_mode",
                "event_source_mappings",
            ],
            check=check_lambda_xray_tracing,
            build_finding=build_lambda_xray_tracing_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-LAMBDA-007",
            name="lambda_code_signing",
            data_source="lambda_functions",
            collection_mode="multiple",
            check_arguments=[
                "function_name",
                "package_type",
                "code_signing_config_arn",
                "code_signing_policy",
            ],
            check=check_lambda_code_signing,
            build_finding=build_lambda_code_signing_finding,
        ),
    ]
)
