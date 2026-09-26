from dataclasses import dataclass
from typing import Callable

from scanner.aws.provider import AWSProvider

from scanner.aws.scanners.ssm import SSMScanner
from scanner.aws.services.ssm import SSMService
from scanner.aws.scanners.cloudtrail_scanner import CloudTrailScanner
from scanner.aws.scanners.ec2 import EC2Scanner
from scanner.aws.scanners.ecr import ECRScanner
from scanner.aws.scanners.sqs import SQSScanner
from scanner.aws.scanners.stepfunctions import StepFunctionsScanner
from scanner.aws.scanners.eventbridge import EventBridgeScanner
from scanner.aws.scanners.dynamodb import DynamoDBScanner
from scanner.aws.scanners.ecs import ECSScanner
from scanner.aws.scanners.api_gateway import APIGatewayScanner
from scanner.aws.scanners.waf import WAFScanner
from scanner.aws.scanners.eks import EKSScanner
from scanner.aws.scanners.secretsmanager import SecretsManagerScanner
from scanner.aws.scanners.acm import ACMScanner
from scanner.aws.scanners.guardduty import GuardDutyScanner
from scanner.aws.scanners.inspector import InspectorScanner
from scanner.aws.scanners.macie import MacieScanner
from scanner.aws.scanners.kinesis import KinesisScanner
from scanner.aws.scanners.ses import SESScanner
from scanner.aws.scanners.cloudwatch import CloudWatchScanner
from scanner.aws.scanners.backup import BackupScanner
from scanner.aws.scanners.route53 import Route53Scanner
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
from scanner.aws.services.api_gateway import APIGatewayService
from scanner.aws.services.waf import WAFService
from scanner.aws.services.eks import EKSService
from scanner.aws.services.secretsmanager import SecretsManagerService
from scanner.aws.services.acm import ACMService
from scanner.aws.services.guardduty import GuardDutyService
from scanner.aws.services.inspector import InspectorService
from scanner.aws.services.macie import MacieService
from scanner.aws.services.kinesis import KinesisService
from scanner.aws.services.ses import SESService
from scanner.aws.services.cloudwatch import CloudWatchService
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
from scanner.aws.services.backup import BackupService
from scanner.aws.services.route53 import Route53Service

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


def _extract_error_code(
    error: Exception,
) -> str | None:
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
    role_arn,
    external_id,
    region_name,
    expected_account_id,
):
    if not role_arn:
        raise RuntimeError(
            "AWS IAM role ARN is not configured"
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
            "AWS account identity mismatch"
        )

    scanners = (
        (
            "s3",
            lambda: S3Scanner(
                S3Service(session)
            ),
        ),
        (
            "iam",
            lambda: IAMScanner(
                IAMService(session)
            ),
        ),
        (
            "kms",
            lambda: KMSScanner(
                KMSService(session)
            ),
        ),
        (
            "ec2",
            lambda: EC2Scanner(
                EC2Service(session)
            ),
        ),
        (
            "rds",
            lambda: RDSScanner(
                RDSService(session)
            ),
        ),
        (
            "lambda",
            lambda: LambdaScanner(
                LambdaService(session)
            ),
        ),
        (
            "vpc",
            lambda: VPCScanner(
                VPCService(session)
            ),
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
            lambda: ECRScanner(
                ECRService(session)
            ),
        ),
        (
            "sqs",
            lambda: SQSScanner(
                SQSService(session)
            ),
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
        (
            "api_gateway",
            lambda: APIGatewayScanner(
                APIGatewayService(session)
            ),
        ),
        (
            "waf",
            lambda: WAFScanner(
                WAFService(session)
            ),
        ),
        (
            "eks",
            lambda: EKSScanner(
                EKSService(session)
            ),
        ),
        (
            "secretsmanager",
            lambda: SecretsManagerScanner(
                SecretsManagerService(session)
            ),
        ),
        (
            "acm",
            lambda: ACMScanner(
                ACMService(session)
            ),
        ),
        (
            "guardduty",
            lambda: GuardDutyScanner(
                GuardDutyService(session)
            ),
        ),
        (
            "inspector",
            lambda: InspectorScanner(
                InspectorService(session)
            ),
        ),
        (
            "macie",
            lambda: MacieScanner(
                MacieService(session)
            ),
        ),
        (
            "kinesis",
            lambda: KinesisScanner(
                KinesisService(session)
            ),
        ),
        (
            "ses",
            lambda: SESScanner(
                SESService(session)
            ),
        ),
        (
            "ssm",
            lambda: SSMScanner(
                SSMService(session)
            ),
        ),
        (
            "cloudwatch",
            lambda: CloudWatchScanner(
                CloudWatchService(session)
            ),
        ),
        (
            "backup",
            lambda: BackupScanner(
                BackupService(session)
            ),
        ),
        (
            "route53",
            lambda: Route53Scanner(
                Route53Service(session)
            ),
        ),
    )

    findings = []
    errors = []

    for service_name, scanner_factory in scanners:
        service_findings, error = _run_scanner(
            service_name,
            scanner_factory,
        )

        findings.extend(service_findings)

        if error is not None:
            errors.append(error)

    return AWSScanResult(
        findings=findings,
        errors=errors,
    )
