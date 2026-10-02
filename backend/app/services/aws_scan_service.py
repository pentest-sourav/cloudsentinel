from dataclasses import dataclass, replace
from typing import Callable

from scanner.aws.provider import AWSProvider
from scanner.aws.client_factory import create_aws_client

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
from scanner.aws.scanners.efs import EFSScanner
from scanner.aws.scanners.elb import ELBScanner
from scanner.aws.scanners.msk import MSKScanner
from scanner.aws.scanners.codebuild import CodeBuildScanner
from scanner.aws.scanners.elasticbeanstalk import ElasticBeanstalkScanner
from scanner.aws.scanners.network_firewall import NetworkFirewallScanner
from scanner.aws.scanners.cloudfront import CloudFrontScanner
from scanner.aws.scanners.route53 import Route53Scanner
from scanner.aws.scanners.redshift import RedshiftScanner
from scanner.aws.scanners.neptune import NeptuneScanner
from scanner.aws.scanners.firehose import FirehoseScanner
from scanner.aws.scanners.emr import EMRScanner
from scanner.aws.scanners.glue import GlueScanner
from scanner.aws.scanners.fsx import FSxScanner
from scanner.aws.scanners.mq import MQScanner
from scanner.aws.scanners.appsync import AppSyncScanner
from scanner.aws.scanners.athena import AthenaScanner
from scanner.aws.scanners.config import ConfigScanner
from scanner.aws.scanners.cloudformation import CloudFormationScanner
from scanner.aws.scanners.amplify import AmplifyScanner
from scanner.aws.scanners.apprunner import AppRunnerScanner
from scanner.aws.scanners.appconfig import AppConfigScanner
from scanner.aws.scanners.appflow import AppFlowScanner
from scanner.aws.scanners.batch import BatchScanner
from scanner.aws.scanners.dms import DMSScanner
from scanner.aws.scanners.datasync import DataSyncScanner
from scanner.aws.scanners.detective import DetectiveScanner
from scanner.aws.scanners.documentdb import DocumentDBScanner
from scanner.aws.scanners.autoscaling import AutoScalingScanner
from scanner.aws.services.autoscaling import AutoScalingService
from scanner.aws.services.mq import MQService
from scanner.aws.services.appsync import AppSyncService
from scanner.aws.services.athena import AthenaService
from scanner.aws.services.config import ConfigService
from scanner.aws.services.cloudformation import CloudFormationService
from scanner.aws.services.amplify import AmplifyService
from scanner.aws.services.apprunner import AppRunnerService
from scanner.aws.services.appconfig import AppConfigService
from scanner.aws.services.appflow import AppFlowService
from scanner.aws.services.batch import BatchService
from scanner.aws.services.dms import DMSService
from scanner.aws.services.datasync import DataSyncService
from scanner.aws.services.detective import DetectiveService
from scanner.aws.services.documentdb import DocumentDBService
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
from scanner.aws.services.efs import EFSService
from scanner.aws.services.elb import ELBService
from scanner.aws.services.msk import MSKService
from scanner.aws.services.codebuild import CodeBuildService
from scanner.aws.services.elasticbeanstalk import ElasticBeanstalkService
from scanner.aws.services.network_firewall import NetworkFirewallService
from scanner.aws.services.cloudfront import CloudFrontService
from scanner.aws.services.route53 import Route53Service
from scanner.aws.services.redshift import RedshiftService
from scanner.aws.services.neptune import NeptuneService
from scanner.aws.services.firehose import FirehoseService
from scanner.aws.services.emr import EMRService
from scanner.aws.services.glue import GlueService
from scanner.aws.services.fsx import FSxService

from scanner.aws.session import create_aws_session
from scanner.aws.region_discovery import discover_aws_regions


@dataclass(frozen=True)
class ScannerExecutionError:
    service: str
    error_type: str
    error_code: str | None
    message: str
    region: str = "unknown"


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
    region: str = "unknown",
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
            region=region,
        )


def _stamp_findings(
    findings: list,
    region: str,
) -> list:
    """Stamp concrete Finding objects with their execution scope."""

    stamped = []

    for finding in findings:
        # Real CloudSentinel Finding objects are dataclasses.
        # Legacy/test Finding-like objects are intentionally left
        # untouched so orchestration does not alter object identity.
        if hasattr(finding, "__dataclass_fields__"):
            try:
                stamped.append(
                    replace(
                        finding,
                        region=region,
                    )
                )
                continue
            except (TypeError, ValueError):
                pass

        try:
            # Support Finding-like immutable objects exposing a
            # dataclass-compatible replace operation.
            stamped.append(
                replace(
                    finding,
                    region=region,
                )
            )
        except (TypeError, ValueError):
            stamped.append(finding)

    return stamped


def _resolve_s3_bucket_regions(
    session,
    findings: list,
) -> list:
    """
    Resolve the actual region of S3 bucket findings.

    S3 inventory is account-wide, therefore the scanner execution
    region is not necessarily the bucket region.
    """

    # Avoid making an unnecessary AWS call when this is only being
    # exercised with legacy/mock findings.
    bucket_findings = [
        finding
        for finding in findings
        if getattr(finding, "resource_type", None) == "s3_bucket"
        and isinstance(getattr(finding, "resource_id", None), str)
        and getattr(finding, "resource_id", None)
    ]

    if not bucket_findings:
        return findings

    s3_client = create_aws_client(session, "s3")
    region_cache: dict[str, str] = {}
    resolved: list = []

    for finding in findings:
        if getattr(finding, "resource_type", None) != "s3_bucket":
            resolved.append(finding)
            continue

        bucket_name = getattr(finding, "resource_id", None)

        if not isinstance(bucket_name, str) or not bucket_name:
            resolved.append(finding)
            continue

        if bucket_name not in region_cache:
            try:
                response = s3_client.get_bucket_location(
                    Bucket=bucket_name,
                )
                location = response.get("LocationConstraint")

                if location in (None, ""):
                    bucket_region = "us-east-1"
                elif location == "EU":
                    bucket_region = "eu-west-1"
                elif isinstance(location, str):
                    bucket_region = location
                else:
                    bucket_region = "unknown"

            except Exception:
                bucket_region = "unknown"

            region_cache[bucket_name] = bucket_region

        bucket_region = region_cache[bucket_name]

        if bucket_region == "unknown":
            resolved.append(finding)
            continue

        try:
            resolved.append(
                replace(
                    finding,
                    region=bucket_region,
                )
            )
        except (TypeError, ValueError):
            # Preserve legacy/mock Finding-like objects.
            resolved.append(finding)

    return resolved


def _build_scanners(
    session,
    identity,
    region_name: str,
):
    return (
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
            "autoscaling",
            lambda: AutoScalingScanner(
                AutoScalingService(
                    session,
                    account_id=identity.account_id,
                    region_name=region_name,
                )
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
                ECSService(
                    create_aws_client(
                        session,
                        "ecs",
                    )
                )
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
            "efs",
            lambda: EFSScanner(
                EFSService(session)
            ),
        ),
        (
            "cloudfront",
            lambda: CloudFrontScanner(
                CloudFrontService(session)
            ),
        ),
        (
            "elb",
            lambda: ELBScanner(
                ELBService(session)
            ),
        ),
        (
            "msk",
            lambda: MSKScanner(
                MSKService(session)
            ),
        ),
        (
            "codebuild",
            lambda: CodeBuildScanner(
                CodeBuildService(session)
            ),
        ),
        (
            "elasticbeanstalk",
            lambda: ElasticBeanstalkScanner(
                ElasticBeanstalkService(session)
            ),
        ),
        (
            "network_firewall",
            lambda: NetworkFirewallScanner(
                NetworkFirewallService(session)
            ),
        ),
        (
            "route53",
            lambda: Route53Scanner(
                Route53Service(session)
            ),
        ),
        (
            "redshift",
            lambda: RedshiftScanner(
                RedshiftService(session)
            ),
        ),
        (
            "neptune",
            lambda: NeptuneScanner(
                NeptuneService(session)
            ),
        ),
        (
            "firehose",
            lambda: FirehoseScanner(
                FirehoseService(session)
            ),
        ),
        (
            "emr",
            lambda: EMRScanner(
                EMRService(session)
            ),
        ),
        (
            "fsx",
            lambda: FSxScanner(
                FSxService(session)
            ),
        ),
        (
            "glue",
            lambda: GlueScanner(
                GlueService(session)
            ),
        ),
        (
            "mq",
            lambda: MQScanner(
                MQService(session)
            ),
        ),
        (
            "appsync",
            lambda: AppSyncScanner(
                AppSyncService(session)
            ),
        ),
        (
            "athena",
            lambda: AthenaScanner(
                AthenaService(
                    session,
                    account_id=identity.account_id,
                    region_name=region_name,
                )
            ),
        ),
        (
            "config",
            lambda: ConfigScanner(
                ConfigService(session)
            ),
        ),
        (
            "cloudformation",
            lambda: CloudFormationScanner(
                CloudFormationService(session)
            ),
        ),
        (
            "amplify",
            lambda: AmplifyScanner(
                AmplifyService(session)
            ),
        ),
        (
            "apprunner",
            lambda: AppRunnerScanner(
                AppRunnerService(session)
            ),
        ),
        (
            "appconfig",
            lambda: AppConfigScanner(
                AppConfigService(
                    session,
                    account_id=identity.account_id,
                    region_name=region_name,
                )
            ),
        ),
        (
            "appflow",
            lambda: AppFlowScanner(
                AppFlowService(session)
            ),
        ),
        (
            "batch",
            lambda: BatchScanner(
                BatchService(session)
            ),
        ),
        (
            "dms",
            lambda: DMSScanner(
                DMSService(session)
            ),
        ),
        (
            "datasync",
            lambda: DataSyncScanner(
                DataSyncService(session)
            ),
        ),
        (
            "detective",
            lambda: DetectiveScanner(
                DetectiveService(session)
            ),
        ),
        (
            "documentdb",
            lambda: DocumentDBScanner(
                DocumentDBService(session)
            ),
        ),
    )


def _run_scanner(
    service_name: str,
    scanner_factory: Callable[[], object],
    region: str = "unknown",
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
            region=region,
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

    # Base session:
    # - verifies account identity
    # - discovers enabled regions
    # - executes global/account-wide services
    # - is reused for the configured region
    base_session = create_aws_session(
        role_arn=role_arn,
        external_id=external_id,
        region_name=region_name,
    )

    provider = AWSProvider(base_session)

    identity = provider.verify_identity()

    if (
        expected_account_id
        and identity.account_id != expected_account_id
    ):
        raise RuntimeError(
            "AWS account identity mismatch"
        )

    discovered_regions = discover_aws_regions(base_session)

    if region_name and region_name not in discovered_regions:
        discovered_regions.append(region_name)

    discovered_regions = sorted(set(discovered_regions))

    if not discovered_regions:
        raise RuntimeError(
            "AWS account has no enabled regions available for scanning"
        )

    # Reuse the base session for the configured region.
    regional_sessions = {}

    if region_name:
        regional_sessions[region_name] = base_session

    # Build the base scanner definitions once. The definitions contain
    # factories, so actual scanner construction remains lazy.
    base_scanners = _build_scanners(
        base_session,
        identity,
        region_name,
    )

    global_services = {
        "iam",
        "cloudfront",
        "route53",
    }

    findings: list = []
    errors: list[ScannerExecutionError] = []

    # ------------------------------------------------------------
    # Execute in the canonical scanner order.
    #
    # Global services: once.
    # S3: once account-wide.
    # WAF: REGIONAL once per region + CLOUDFRONT once globally.
    # Everything else: once per discovered region.
    #
    # This preserves the historical scanner ordering while adding
    # correct multi-region execution.
    # ------------------------------------------------------------

    for service_name, base_factory in base_scanners:

        # --------------------------------------------------------
        # Global/account-wide service
        # --------------------------------------------------------
        if service_name in global_services:
            service_findings, error = _run_scanner(
                service_name,
                base_factory,
                region="global",
            )

            findings.extend(
                _stamp_findings(
                    service_findings,
                    "global",
                )
            )

            if error is not None:
                errors.append(error)

            continue

        # --------------------------------------------------------
        # S3 account-wide inventory
        # --------------------------------------------------------
        if service_name == "s3":
            service_findings, error = _run_scanner(
                service_name,
                base_factory,
                region="global",
            )

            if service_findings:
                service_findings = _resolve_s3_bucket_regions(
                    base_session,
                    service_findings,
                )

            findings.extend(service_findings)

            if error is not None:
                errors.append(error)

            continue

        # --------------------------------------------------------
        # WAF special handling
        # --------------------------------------------------------
        if service_name == "waf":

            # Regional WAF ACLs/rule groups.
            for current_region in discovered_regions:
                regional_session = regional_sessions.get(
                    current_region
                )

                if regional_session is None:
                    regional_session = create_aws_session(
                        role_arn=role_arn,
                        external_id=external_id,
                        region_name=current_region,
                    )
                    regional_sessions[current_region] = regional_session

                regional_factory = (
                    lambda session=regional_session: WAFScanner(
                        WAFService(session),
                        scopes=("REGIONAL",),
                    )
                )

                service_findings, error = _run_scanner(
                    "waf",
                    regional_factory,
                    region=current_region,
                )

                findings.extend(
                    _stamp_findings(
                        service_findings,
                        current_region,
                    )
                )

                if error is not None:
                    errors.append(error)

            # CloudFront WAF uses the WAF us-east-1 endpoint.
            # WAFService creates that client explicitly, so a second
            # AWS session is NOT required.
            waf_global_factory = lambda: WAFScanner(
                WAFService(base_session),
                scopes=("CLOUDFRONT",),
            )

            service_findings, error = _run_scanner(
                "waf-cloudfront",
                waf_global_factory,
                region="global",
            )

            findings.extend(
                _stamp_findings(
                    service_findings,
                    "global",
                )
            )

            if error is not None:
                errors.append(error)

            continue

        # --------------------------------------------------------
        # All remaining services are regional.
        # --------------------------------------------------------
        for current_region in discovered_regions:

            regional_session = regional_sessions.get(
                current_region
            )

            if regional_session is None:
                regional_session = create_aws_session(
                    role_arn=role_arn,
                    external_id=external_id,
                    region_name=current_region,
                )
                regional_sessions[current_region] = regional_session

            regional_scanners = _build_scanners(
                regional_session,
                identity,
                current_region,
            )

            regional_factory = next(
                scanner_factory
                for name, scanner_factory in regional_scanners
                if name == service_name
            )

            service_findings, error = _run_scanner(
                service_name,
                regional_factory,
                region=current_region,
            )

            findings.extend(
                _stamp_findings(
                    service_findings,
                    current_region,
                )
            )

            if error is not None:
                errors.append(error)

    return AWSScanResult(
        findings=findings,
        errors=errors,
    )
