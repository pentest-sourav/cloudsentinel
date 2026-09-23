from engine.rules.aws.lambda_rules.not_in_vpc import (
    build_lambda_not_in_vpc_finding,
    check_lambda_not_in_vpc,
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


def test_lambda_003_detects_unsupported_runtime():
    result = check_unsupported_lambda_runtime(
        function_name="legacy-function",
        runtime="python3.9",
        package_type="Zip",
    )

    assert result is not None
    assert result.function_name == "legacy-function"
    assert result.runtime == "python3.9"


def test_lambda_003_ignores_supported_runtime():
    result = check_unsupported_lambda_runtime(
        function_name="current-function",
        runtime="python3.12",
        package_type="Zip",
    )

    assert result is None


def test_lambda_003_ignores_container_image_function():
    result = check_unsupported_lambda_runtime(
        function_name="container-function",
        runtime=None,
        package_type="Image",
    )

    assert result is None


def test_lambda_003_builds_medium_finding():
    result = check_unsupported_lambda_runtime(
        function_name="legacy-function",
        runtime="nodejs20.x",
        package_type="Zip",
    )

    assert result is not None

    finding = build_unsupported_lambda_runtime_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-003"
    assert finding.severity.value == "medium"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "legacy-function"
    assert finding.evidence["runtime"] == "nodejs20.x"


def test_lambda_004_detects_function_outside_vpc():
    result = check_lambda_not_in_vpc(
        function_name="public-network-function",
        vpc_id=None,
        subnet_ids=[],
    )

    assert result is not None


def test_lambda_004_ignores_vpc_function():
    result = check_lambda_not_in_vpc(
        function_name="vpc-function",
        vpc_id="vpc-12345678",
        subnet_ids=["subnet-a"],
    )

    assert result is None


def test_lambda_004_builds_low_finding():
    result = check_lambda_not_in_vpc(
        function_name="public-network-function",
        vpc_id=None,
        subnet_ids=[],
    )

    assert result is not None

    finding = build_lambda_not_in_vpc_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-004"
    assert finding.severity.value == "low"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "public-network-function"
    assert finding.evidence["vpc_configured"] is False


def test_lambda_005_ignores_non_vpc_function():
    result = check_lambda_vpc_multi_az(
        function_name="non-vpc-function",
        vpc_id=None,
        subnet_ids=[],
        subnet_availability_zones={},
    )

    assert result is None


def test_lambda_005_detects_single_az_vpc_function():
    result = check_lambda_vpc_multi_az(
        function_name="single-az-function",
        vpc_id="vpc-12345678",
        subnet_ids=[
            "subnet-a",
            "subnet-b",
        ],
        subnet_availability_zones={
            "subnet-a": "eu-north-1a",
            "subnet-b": "eu-north-1a",
        },
    )

    assert result is not None
    assert result.availability_zones == ["eu-north-1a"]


def test_lambda_005_detects_only_one_subnet():
    result = check_lambda_vpc_multi_az(
        function_name="single-subnet-function",
        vpc_id="vpc-12345678",
        subnet_ids=["subnet-a"],
        subnet_availability_zones={
            "subnet-a": "eu-north-1a",
        },
    )

    assert result is not None


def test_lambda_005_ignores_multi_az_vpc_function():
    result = check_lambda_vpc_multi_az(
        function_name="multi-az-function",
        vpc_id="vpc-12345678",
        subnet_ids=[
            "subnet-a",
            "subnet-b",
        ],
        subnet_availability_zones={
            "subnet-a": "eu-north-1a",
            "subnet-b": "eu-north-1b",
        },
    )

    assert result is None


def test_lambda_005_does_not_guess_when_az_data_is_incomplete():
    result = check_lambda_vpc_multi_az(
        function_name="incomplete-data-function",
        vpc_id="vpc-12345678",
        subnet_ids=[
            "subnet-a",
            "subnet-b",
        ],
        subnet_availability_zones={
            "subnet-a": "eu-north-1a",
        },
    )

    assert result is None


def test_lambda_005_builds_medium_finding():
    result = check_lambda_vpc_multi_az(
        function_name="single-az-function",
        vpc_id="vpc-12345678",
        subnet_ids=[
            "subnet-a",
            "subnet-b",
        ],
        subnet_availability_zones={
            "subnet-a": "eu-north-1a",
            "subnet-b": "eu-north-1a",
        },
    )

    assert result is not None

    finding = build_lambda_vpc_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-005"
    assert finding.severity.value == "medium"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "single-az-function"
    assert finding.evidence["availability_zones"] == [
        "eu-north-1a"
    ]
    assert finding.evidence["minimum_availability_zones"] == 2


def test_lambda_006_detects_disabled_xray():
    result = check_lambda_xray_tracing(
        function_name="untraced-function",
        tracing_mode="PassThrough",
        event_source_mappings=[],
    )

    assert result is not None
    assert result.tracing_mode == "PassThrough"


def test_lambda_006_detects_missing_xray_mode():
    result = check_lambda_xray_tracing(
        function_name="untraced-function",
        tracing_mode=None,
        event_source_mappings=[],
    )

    assert result is not None


def test_lambda_006_ignores_active_xray():
    result = check_lambda_xray_tracing(
        function_name="traced-function",
        tracing_mode="Active",
        event_source_mappings=[],
    )

    assert result is None


def test_lambda_006_skips_amazon_msk():
    result = check_lambda_xray_tracing(
        function_name="msk-function",
        tracing_mode="PassThrough",
        event_source_mappings=[
            {
                "EventSourceArn": (
                    "arn:aws:kafka:eu-north-1:"
                    "123456789012:cluster/example/abc"
                ),
                "AmazonManagedKafkaEventSourceConfig": {},
            }
        ],
    )

    assert result is None


def test_lambda_006_skips_self_managed_kafka():
    result = check_lambda_xray_tracing(
        function_name="kafka-function",
        tracing_mode="PassThrough",
        event_source_mappings=[
            {
                "SelfManagedEventSource": {
                    "Endpoints": {
                        "KAFKA_BOOTSTRAP_SERVERS": [
                            "kafka.example.com:9092"
                        ]
                    }
                },
                "SelfManagedKafkaEventSourceConfig": {},
            }
        ],
    )

    assert result is None


def test_lambda_006_skips_amazon_mq():
    result = check_lambda_xray_tracing(
        function_name="mq-function",
        tracing_mode="PassThrough",
        event_source_mappings=[
            {
                "EventSourceArn": (
                    "arn:aws:mq:eu-north-1:"
                    "123456789012:broker/example/abc"
                )
            }
        ],
    )

    assert result is None


def test_lambda_006_skips_documentdb():
    result = check_lambda_xray_tracing(
        function_name="docdb-function",
        tracing_mode="PassThrough",
        event_source_mappings=[
            {
                "EventSourceArn": (
                    "arn:aws:docdb:eu-north-1:"
                    "123456789012:cluster/example"
                ),
                "DocumentDBEventSourceConfig": {},
            }
        ],
    )

    assert result is None


def test_lambda_006_builds_low_finding():
    result = check_lambda_xray_tracing(
        function_name="untraced-function",
        tracing_mode="PassThrough",
        event_source_mappings=[],
    )

    assert result is not None

    finding = build_lambda_xray_tracing_finding(result)

    assert finding.rule_id == "CS-AWS-LAMBDA-006"
    assert finding.severity.value == "low"
    assert finding.resource_type == "lambda_function"
    assert finding.resource_id == "untraced-function"
    assert finding.evidence["xray_active"] is False
