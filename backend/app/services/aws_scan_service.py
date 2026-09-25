from dataclasses import dataclass
from typing import Callable

from scanner.aws.provider import AWSProvider
from scanner.aws.scanners.cloudtrail_scanner import CloudTrailScanner
from scanner.aws.scanners.ec2 import EC2Scanner
from scanner.aws.scanners.ecr import ECRScanner
from scanner.aws.scanners.sqs import SQSScanner
from scanner.aws.scanners.stepfunctions import StepFunctionsScanner
from scanner.aws.scanners.eventbridge import EventBridgeScanner
from scanner.aws.scanners.dynamodb import DynamoDBScanner
from scanner.aws.scanners.ecs import ECSScanner
from scanner.aws.scanners.opensearch import OpenSearchScanner
from scanner.aws.scanners.elasticache import ElastiCacheScanner
from scanner.aws.scanners.iam import IAMScanner
from scanner.aws.scanners.kms import KMSScanner
from scanner.aws.scanners.rds import RDSScanner
from scanner.aws.scanners.lambda_scanner import LambdaScanner
from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.scanners.sns import SNSScanner
from scanner.aws.scanners.vpc_scanner import VPCScanner
from scanner.aws.scanners.security_group_scanner import SecurityGroupScanner
from scanner.aws.scanners.route_table_scanner import RouteTableScanner

from scanner.aws.services.lambda_service import LambdaService
from scanner.aws.services.ec2 import EC2Service
from scanner.aws.services.ecr import ECRService
from scanner.aws.services.sqs import SQSService
from scanner.aws.services.stepfunctions import StepFunctionsService
from scanner.aws.services.eventbridge import EventBridgeService
from scanner.aws.services.dynamodb import DynamoDBService
from scanner.aws.services.ecs import ECSService
from scanner.aws.services.opensearch import OpenSearchService
from scanner.aws.services.elasticache import ElastiCacheService
from scanner.aws.services.iam import IAMService
from scanner.aws.services.kms import KMSService
from scanner.aws.services.rds import RDSService
from scanner.aws.services.s3 import S3Service
from scanner.aws.services.sns import SNSService
from scanner.aws.services.cloudtrail import CloudTrailService
from scanner.aws.services.vpc import VPCService
from scanner.aws.services.security_groups import SecurityGroupService
from scanner.aws.services.route_tables import RouteTableService

from scanner.aws.session import create_aws_session


@dataclass(frozen=True)
class ScannerExecutionError:
    service: str
    error_type: str
    error_code: str | None
    message: str


@dataclass(frozen=True)
class AWSScanResult:
    findings: list
    errors: list[ScannerExecutionError]


def _extract_error_code(error: Exception) -> str | None:
    response = getattr(error, "response", None)

    if isinstance(response, dict):
        error_data = response.get("Error")

        if isinstance(error_data, dict):
            code = error_data.get("Code")

            if code:
                return str(code)

    return None


def _run_scanner(
    service_name: str,
    scanner_factory: Callable[[], object],
) -> tuple[list, ScannerExecutionError | None]:
    try:
        scanner = scanner_factory()
        findings = scanner.scan()
        return findings, None
    except Exception as exc:
        return [], ScannerExecutionError(
            service=service_name,
            error_type=type(exc).__name__,
            error_code=_extract_error_code(exc),
            message=str(exc),
        )


def run_aws_scan(
    role_arn: str | None,
    external_id: str | None,
    region_name: str | None,
    expected_account_id: str | None,
) -> AWSScanResult:
    """
    Run all enabled AWS security scanners against a configured
    CloudSentinel AWS account.

    AWS access is established through STS AssumeRole. The returned
    temporary credentials are used by one boto3 session shared by
    all scanners.

    AWS account identity is verified through STS before any security
    scanner is executed.

    Individual security scanners are isolated from one another.
    A failure in one scanner is recorded as an execution error and
    does not prevent the remaining scanners from running.
    """

    if not role_arn:
        raise RuntimeError(
            "AWS IAM role ARN is not configured for this cloud account."
        )

    session = create_aws_session(
        role_arn=role_arn,
        external_id=external_id,
        region_name=region_name,
    )

    provider = AWSProvider(session)
    identity = provider.verify_identity()

    if (
        expected_account_id
        and identity.account_id != expected_account_id
    ):
        raise RuntimeError(
            "AWS account identity mismatch: expected "
            f"{expected_account_id}, got {identity.account_id}."
        )

    scanners = (
        (
            "s3",
            lambda: S3Scanner(S3Service(session)),
        ),
        (
            "iam",
            lambda: IAMScanner(IAMService(session)),
        ),
        (
            "kms",
            lambda: KMSScanner(KMSService(session)),
        ),
        (
            "ec2",
            lambda: EC2Scanner(EC2Service(session)),
        ),
        (
            "rds",
            lambda: RDSScanner(RDSService(session)),
        ),
        (
            "lambda",
            lambda: LambdaScanner(LambdaService(session)),
        ),
        (
            "vpc",
            lambda: VPCScanner(VPCService(session)),
        ),
        (
            "security_group",
            lambda: SecurityGroupScanner(
                SecurityGroupService(session)
            ),
        ),
        (
            "route_table",
            lambda: RouteTableScanner(
                RouteTableService(session)
            ),
        ),
        (
            "cloudtrail",
            lambda: CloudTrailScanner(
                CloudTrailService(session)
            ),
        ),
        (
            "sns",
            lambda: SNSScanner(
                SNSService(
                    session,
                    region_name=session.region_name,
                )
            ),
        ),
        (
            "ecr",
            lambda: ECRScanner(ECRService(session)),
        ),
        (
            "sqs",
            lambda: SQSScanner(SQSService(session)),
        ),
        (
            "stepfunctions",
            lambda: StepFunctionsScanner(
                StepFunctionsService(session)
            ),
        ),
        (
            "eventbridge",
            lambda: EventBridgeScanner(
                EventBridgeService(session)
            ),
        ),
        (
            "opensearch",
            lambda: OpenSearchScanner(
                OpenSearchService(session)
            ),
        ),
        (
            "elasticache",
            lambda: ElastiCacheScanner(
                ElastiCacheService(session)
            ),
        ),
        (
            "dynamodb",
            lambda: DynamoDBScanner(
                DynamoDBService(session)
            ),
        ),
        (
            "ecs",
            lambda: ECSScanner(
                ECSService(session)
            ),
        ),
    )

    findings = []
    errors: list[ScannerExecutionError] = []

    for service_name, scanner_factory in scanners:
        service_findings, execution_error = _run_scanner(
            service_name=service_name,
            scanner_factory=scanner_factory,
        )

        findings.extend(service_findings)

        if execution_error is not None:
            errors.append(execution_error)

    return AWSScanResult(
        findings=findings,
        errors=errors,
    )
