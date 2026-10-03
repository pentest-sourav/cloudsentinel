from contextlib import ExitStack, contextmanager
from unittest.mock import Mock, patch

import pytest

from backend.app.services.aws_scan_service import run_aws_scan


ROLE_ARN = (
    "arn:aws:iam::123456789012:"
    "role/CloudSentinelAuditRole"
)

EXTERNAL_ID = "cloudsentinel-test-external-id"
REGION = "ap-south-1"
ACCOUNT_ID = "123456789012"


def make_mocks():
    scanners = {
        "s3": Mock(),
        "iam": Mock(),
        "kms": Mock(),
        "ec2": Mock(),
        "rds": Mock(),
        "lambda": Mock(),
        "vpc": Mock(),
        "security_group": Mock(),
        "route_table": Mock(),
        "cloudtrail": Mock(),
        "sns": Mock(),
        "ecr": Mock(),
        "sqs": Mock(),
        "stepfunctions": Mock(),
        "eventbridge": Mock(),
        "dynamodb": Mock(),
        "opensearch": Mock(),
        "elasticache": Mock(),
        "ecs": Mock(),
        "api_gateway": Mock(),
        "waf": Mock(),
        "eks": Mock(),
        "secretsmanager": Mock(),
        "acm": Mock(),
        "guardduty": Mock(),
        "securityhub": Mock(),
        "inspector": Mock(),
        "macie": Mock(),
        "kinesis": Mock(),
        "ses": Mock(),
        "ssm": Mock(),
        "cloudwatch": Mock(),
        "backup": Mock(),
        "efs": Mock(),
        "elb": Mock(),
        "msk": Mock(),
        "cloudfront": Mock(),
        "codebuild": Mock(),
        "elasticbeanstalk": Mock(),
        "network_firewall": Mock(),
        "route53": Mock(),
        "redshift": Mock(),
        "neptune": Mock(),
        "firehose": Mock(),
        "emr": Mock(),
        "fsx": Mock(),
        "glue": Mock(),
        "mq": Mock(),
        "appsync": Mock(),
        "athena": Mock(),
        "autoscaling": Mock(),
        "config": Mock(),
        "cloudformation": Mock(),
        "amplify": Mock(),
        "apprunner": Mock(),
        "appconfig": Mock(),
        "appflow": Mock(),
        "batch": Mock(),
        "dms": Mock(),
        "datasync": Mock(),
        "detective": Mock(),
        "documentdb": Mock(),
    }

    services = {
        "s3": Mock(),
        "iam": Mock(),
        "kms": Mock(),
        "ec2": Mock(),
        "rds": Mock(),
        "lambda": Mock(),
        "vpc": Mock(),
        "security_group": Mock(),
        "route_table": Mock(),
        "cloudtrail": Mock(),
        "sns": Mock(),
        "ecr": Mock(),
        "sqs": Mock(),
        "stepfunctions": Mock(),
        "eventbridge": Mock(),
        "dynamodb": Mock(),
        "opensearch": Mock(),
        "elasticache": Mock(),
        "ecs": Mock(),
        "api_gateway": Mock(),
        "waf": Mock(),
        "eks": Mock(),
        "secretsmanager": Mock(),
        "acm": Mock(),
        "guardduty": Mock(),
        "securityhub": Mock(),
        "inspector": Mock(),
        "macie": Mock(),
        "kinesis": Mock(),
        "ses": Mock(),
        "ssm": Mock(),
        "cloudwatch": Mock(),
        "backup": Mock(),
        "efs": Mock(),
        "elb": Mock(),
        "msk": Mock(),
        "cloudfront": Mock(),
        "codebuild": Mock(),
        "elasticbeanstalk": Mock(),
        "network_firewall": Mock(),
        "route53": Mock(),
        "redshift": Mock(),
        "neptune": Mock(),
        "firehose": Mock(),
        "emr": Mock(),
        "fsx": Mock(),
        "glue": Mock(),
        "mq": Mock(),
        "appsync": Mock(),
        "athena": Mock(),
        "autoscaling": Mock(),
        "config": Mock(),
        "cloudformation": Mock(),
        "amplify": Mock(),
        "apprunner": Mock(),
        "appconfig": Mock(),
        "appflow": Mock(),
        "batch": Mock(),
        "dms": Mock(),
        "datasync": Mock(),
        "detective": Mock(),
        "documentdb": Mock(),
    }

    findings = {
        "s3": Mock(rule_id="CS-AWS-S3-001"),
        "iam": Mock(rule_id="CS-AWS-IAM-001"),
        "kms": Mock(rule_id="CS-AWS-KMS-001"),
        "ec2": Mock(rule_id="CS-AWS-EC2-001"),
        "rds": Mock(rule_id="CS-AWS-RDS-001"),
        "lambda": Mock(rule_id="CS-AWS-LAMBDA-001"),
        "vpc": Mock(rule_id="CS-AWS-VPC-001"),
        "security_group": Mock(rule_id="CS-AWS-SG-001"),
        "route_table": Mock(rule_id="CS-AWS-RT-001"),
        "cloudtrail": Mock(rule_id="CS-AWS-CT-001"),
        "sns": Mock(rule_id="CS-AWS-SNS-001"),
        "ecr": Mock(rule_id="CS-AWS-ECR-001"),
        "sqs": Mock(rule_id="CS-AWS-SQS-001"),
        "stepfunctions": Mock(rule_id="CS-AWS-SFN-001"),
        "eventbridge": Mock(
            rule_id="CS-AWS-EVENTBRIDGE-002"
        ),
        "dynamodb": Mock(
            rule_id="CS-AWS-DYNAMODB-001"
        ),
        "opensearch": Mock(
            rule_id="CS-AWS-OPENSEARCH-001"
        ),
        "elasticache": Mock(
            rule_id="CS-AWS-ELASTICACHE-001"
        ),
        "ecs": Mock(
            rule_id="CS-AWS-ECS-002"
        ),
        "api_gateway": Mock(
            rule_id="CS-AWS-APIGATEWAY-001"
        ),
        "waf": Mock(
            rule_id="CS-AWS-WAF-010"
        ),
        "eks": Mock(
            rule_id="CS-AWS-EKS-001"
        ),
        "secretsmanager": Mock(
            rule_id="CS-AWS-SECRETSMANAGER-001"
        ),
        "acm": Mock(
            rule_id="CS-AWS-ACM-001"
        ),
        "guardduty": Mock(
            rule_id="CS-AWS-GD-001"
        ),
        "securityhub": Mock(
            rule_id="CS-AWS-SH-001"
        ),
        "inspector": Mock(
            rule_id="CS-AWS-INSPECTOR-001"
        ),
        "macie": Mock(
            rule_id="CS-AWS-MACIE-001"
        ),
        "kinesis": Mock(
            rule_id="CS-AWS-KINESIS-001"
        ),
        "ses": Mock(
            rule_id="CS-AWS-SES-001"
        ),
        "ssm": Mock(
            rule_id="CS-AWS-SSM-001"
        ),
        "cloudwatch": Mock(
            rule_id="CS-AWS-CLOUDWATCH-001"
        ),
        "backup": Mock(
            rule_id="CS-AWS-BACKUP-001"
        ),
        "efs": Mock(
            rule_id="CS-AWS-EFS-001"
        ),
        "elb": Mock(
            rule_id="CS-AWS-ELB-001"
        ),
        "msk": Mock(
            rule_id="CS-AWS-MSK-001"
        ),
        "cloudfront": Mock(
            rule_id="CS-AWS-CLOUDFRONT-001"
        ),
        "codebuild": Mock(
            rule_id="CS-AWS-CODEBUILD-001"
        ),
        "elasticbeanstalk": Mock(
            rule_id="CS-AWS-ELASTICBEANSTALK-001"
        ),
        "network_firewall": Mock(
            rule_id="CS-AWS-NETWORKFIREWALL-001"
        ),
        "route53": Mock(
            rule_id="CS-AWS-ROUTE53-001"
        ),
        "redshift": Mock(
            rule_id="CS-AWS-REDSHIFT-001"
        ),
        "neptune": Mock(
            rule_id="CS-AWS-NEPTUNE-001"
        ),
        "firehose": Mock(
            rule_id="CS-AWS-FIREHOSE-001"
        ),
        "emr": Mock(
            rule_id="CS-AWS-EMR-001"
        ),
        "fsx": Mock(
            rule_id="CS-AWS-FSX-001"
        ),
        "glue": Mock(
            rule_id="CS-AWS-GLUE-001"
        ),
        "mq": Mock(
            rule_id="CS-AWS-MQ-002"
        ),
        "appsync": Mock(
            rule_id="CS-AWS-APPSYNC-005"
        ),
        "athena": Mock(
            rule_id="CS-AWS-ATHENA-004"
        ),
        "autoscaling": Mock(
            rule_id="CS-AWS-AUTOSCALING-001"
        ),
        "config": Mock(
            rule_id="CS-AWS-CONFIG-001"
        ),
        "cloudformation": Mock(
            rule_id="CS-AWS-CLOUDFORMATION-002"
        ),
        "amplify": Mock(
            rule_id="CS-AWS-AMPLIFY-001"
        ),
        "apprunner": Mock(
            rule_id="CS-AWS-APPRUNNER-001"
        ),
        "appconfig": Mock(
            rule_id="CS-AWS-APPCONFIG-001"
        ),
        "appflow": Mock(
            rule_id="CS-AWS-APPFLOW-001"
        ),
        "batch": Mock(
            rule_id="CS-AWS-BATCH-001"
        ),
        "dms": Mock(
            rule_id="CS-AWS-DMS-001"
        ),
        "datasync": Mock(
            rule_id="CS-AWS-DATASYNC-001"
        ),
        "detective": Mock(
            rule_id="CS-AWS-DETECTIVE-001"
        ),
        "documentdb": Mock(
            rule_id="CS-AWS-DOCUMENTDB-001"
        ),
    }

    for name, scanner in scanners.items():
        scanner.scan.return_value = [findings[name]]

    return scanners, services, findings


@contextmanager
def patch_aws_scanners(
    scanners,
    services,
    fake_session,
    fake_provider,
):
    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "backend.app.services.aws_scan_service.discover_aws_regions",
                return_value=[REGION],
            )
        )

        mock_session = stack.enter_context(
            patch(
                "backend.app.services.aws_scan_service.create_aws_session",
                return_value=fake_session,
            )
        )

        stack.enter_context(
            patch(
                "backend.app.services.aws_scan_service.AWSProvider",
                return_value=fake_provider,
            )
        )

        service_scanner_pairs = (
            ("S3Service", "S3Scanner", "s3"),
            ("IAMService", "IAMScanner", "iam"),
            ("KMSService", "KMSScanner", "kms"),
            ("EC2Service", "EC2Scanner", "ec2"),
            ("RDSService", "RDSScanner", "rds"),
            ("LambdaService", "LambdaScanner", "lambda"),
            ("VPCService", "VPCScanner", "vpc"),
            (
                "SecurityGroupService",
                "SecurityGroupScanner",
                "security_group",
            ),
            (
                "RouteTableService",
                "RouteTableScanner",
                "route_table",
            ),
            (
                "CloudTrailService",
                "CloudTrailScanner",
                "cloudtrail",
            ),
            ("SNSService", "SNSScanner", "sns"),
            ("ECRService", "ECRScanner", "ecr"),
            ("SQSService", "SQSScanner", "sqs"),
            (
                "StepFunctionsService",
                "StepFunctionsScanner",
                "stepfunctions",
            ),
            (
                "EventBridgeService",
                "EventBridgeScanner",
                "eventbridge",
            ),
            (
                "DynamoDBService",
                "DynamoDBScanner",
                "dynamodb",
            ),
            (
                "OpenSearchService",
                "OpenSearchScanner",
                "opensearch",
            ),
            (
                "ElastiCacheService",
                "ElastiCacheScanner",
                "elasticache",
            ),
            ("ECSService", "ECSScanner", "ecs"),
            (
                "APIGatewayService",
                "APIGatewayScanner",
                "api_gateway",
            ),
            (
                "WAFService",
                "WAFScanner",
                "waf",
            ),
            (
                "EKSService",
                "EKSScanner",
                "eks",
            ),
            (
                "SecretsManagerService",
                "SecretsManagerScanner",
                "secretsmanager",
            ),
            (
                "ACMService",
                "ACMScanner",
                "acm",
            ),
            (
                "GuardDutyService",
                "GuardDutyScanner",
                "guardduty",
            ),
            (
                "SecurityHubService",
                "SecurityHubScanner",
                "securityhub",
            ),
            (
                "InspectorService",
                "InspectorScanner",
                "inspector",
            ),
            (
                "MacieService",
                "MacieScanner",
                "macie",
            ),
            (
                "KinesisService",
                "KinesisScanner",
                "kinesis",
            ),
            (
                "SESService",
                "SESScanner",
                "ses",
            ),
            (
                "SSMService",
                "SSMScanner",
                "ssm",
            ),
            (
                "CloudWatchService",
                "CloudWatchScanner",
                "cloudwatch",
            ),
            (
                "BackupService",
                "BackupScanner",
                "backup",
            ),
            (
                "EFSService",
                "EFSScanner",
                "efs",
            ),
            (
                "ELBService",
                "ELBScanner",
                "elb",
            ),
            (
                "MSKService",
                "MSKScanner",
                "msk",
            ),
            (
                "CloudFrontService",
                "CloudFrontScanner",
                "cloudfront",
            ),
            (
                "CodeBuildService",
                "CodeBuildScanner",
                "codebuild",
            ),
            (
                "ElasticBeanstalkService",
                "ElasticBeanstalkScanner",
                "elasticbeanstalk",
            ),
            (
                "NetworkFirewallService",
                "NetworkFirewallScanner",
                "network_firewall",
            ),
            (
                "Route53Service",
                "Route53Scanner",
                "route53",
            ),
            (
                "RedshiftService",
                "RedshiftScanner",
                "redshift",
            ),
            (
                "NeptuneService",
                "NeptuneScanner",
                "neptune",
            ),
            (
                "FirehoseService",
                "FirehoseScanner",
                "firehose",
            ),
            (
                "EMRService",
                "EMRScanner",
                "emr",
            ),
            (
                "FSxService",
                "FSxScanner",
                "fsx",
            ),
            (
                "GlueService",
                "GlueScanner",
                "glue",
            ),
            (
                "MQService",
                "MQScanner",
                "mq",
            ),
            (
                "AppSyncService",
                "AppSyncScanner",
                "appsync",
            ),
            (
                "AthenaService",
                "AthenaScanner",
                "athena",
            ),
            (
                "AutoScalingService",
                "AutoScalingScanner",
                "autoscaling",
            ),
            (
                "ConfigService",
                "ConfigScanner",
                "config",
            ),
            (
                "CloudFormationService",
                "CloudFormationScanner",
                "cloudformation",
            ),
            (
                "AmplifyService",
                "AmplifyScanner",
                "amplify",
            ),
            (
                "AppRunnerService",
                "AppRunnerScanner",
                "apprunner",
            ),
            (
                "AppConfigService",
                "AppConfigScanner",
                "appconfig",
            ),
            (
                "AppFlowService",
                "AppFlowScanner",
                "appflow",
            ),
            (
                "BatchService",
                "BatchScanner",
                "batch",
            ),
            (
                "DMSService",
                "DMSScanner",
                "dms",
            ),
            (
                "DataSyncService",
                "DataSyncScanner",
                "datasync",
            ),
            (
                "DetectiveService",
                "DetectiveScanner",
                "detective",
            ),
            (
                "DocumentDBService",
                "DocumentDBScanner",
                "documentdb",
            ),
        )

        for service_name, scanner_name, key in service_scanner_pairs:
            stack.enter_context(
                patch(
                    f"backend.app.services.aws_scan_service.{service_name}",
                    return_value=services[key],
                )
            )

            stack.enter_context(
                patch(
                    f"backend.app.services.aws_scan_service.{scanner_name}",
                    return_value=scanners[key],
                )
            )

        yield mock_session


def test_run_aws_scan_runs_all_scanners_after_identity_verification():
    scanners, services, findings = make_mocks()

    fake_session = Mock()
    fake_provider = Mock()
    fake_provider.verify_identity.return_value = Mock(
        account_id=ACCOUNT_ID,
    )

    with patch_aws_scanners(
        scanners,
        services,
        fake_session,
        fake_provider,
    ) as mock_session:
        result = run_aws_scan(
            role_arn=ROLE_ARN,
            external_id=EXTERNAL_ID,
            region_name=REGION,
            expected_account_id=ACCOUNT_ID,
        )

    mock_session.assert_called_once_with(
        role_arn=ROLE_ARN,
        external_id=EXTERNAL_ID,
        region_name=REGION,
        role_session_name="CloudSentinelScan",
        duration_seconds=900,
    )

    fake_provider.verify_identity.assert_called_once()

    assert result.findings == [
        findings["s3"],
        findings["iam"],
        findings["kms"],
        findings["ec2"],
        findings["autoscaling"],
        findings["rds"],
        findings["lambda"],
        findings["vpc"],
        findings["security_group"],
        findings["route_table"],
        findings["cloudtrail"],
        findings["sns"],
        findings["ecr"],
        findings["sqs"],
        findings["stepfunctions"],
        findings["eventbridge"],
        findings["opensearch"],
        findings["elasticache"],
        findings["dynamodb"],
        findings["ecs"],
        findings["api_gateway"],
        findings["waf"],
        findings["waf"],
        findings["eks"],
        findings["secretsmanager"],
        findings["acm"],
        findings["guardduty"],
        findings["securityhub"],
        findings["inspector"],
        findings["macie"],
        findings["kinesis"],
        findings["ses"],
        findings["ssm"],
        findings["cloudwatch"],
        findings["backup"],
        findings["efs"],
        findings["cloudfront"],
        findings["elb"],
        findings["msk"],
        findings["codebuild"],
        findings["elasticbeanstalk"],
        findings["network_firewall"],
        findings["route53"],
        findings["redshift"],
        findings["neptune"],
        findings["firehose"],
        findings["emr"],
        findings["fsx"],
        findings["glue"],
        findings["mq"],
        findings["appsync"],
        findings["athena"],
        findings["config"],
        findings["cloudformation"],
        findings["amplify"],
        findings["apprunner"],
        findings["appconfig"],
        findings["appflow"],
        findings["batch"],
        findings["dms"],
        findings["datasync"],
        findings["detective"],
        findings["documentdb"],
    ]

    assert result.errors == []

    for name, scanner in scanners.items():
        if name == "waf":
            assert scanner.scan.call_count == 2
        else:
            scanner.scan.assert_called_once()


def test_run_aws_scan_rejects_missing_role_arn():
    with pytest.raises(
        RuntimeError,
        match="AWS IAM role ARN is not configured",
    ):
        run_aws_scan(
            role_arn=None,
            external_id=None,
            region_name=REGION,
            expected_account_id=ACCOUNT_ID,
        )


def test_run_aws_scan_rejects_account_identity_mismatch():
    fake_session = Mock()
    fake_provider = Mock()

    fake_provider.verify_identity.return_value = Mock(
        account_id="999999999999",
    )

    with patch(
        "backend.app.services.aws_scan_service.create_aws_session",
        return_value=fake_session,
    ), patch(
        "backend.app.services.aws_scan_service.AWSProvider",
        return_value=fake_provider,
    ):
        with pytest.raises(
            RuntimeError,
            match="AWS account identity mismatch",
        ):
            run_aws_scan(
                role_arn=ROLE_ARN,
                external_id=EXTERNAL_ID,
                region_name=REGION,
                expected_account_id=ACCOUNT_ID,
            )


def test_run_aws_scan_allows_scan_when_expected_account_id_is_missing():
    scanners, services, findings = make_mocks()

    fake_session = Mock()
    fake_provider = Mock()
    fake_provider.verify_identity.return_value = Mock(
        account_id=ACCOUNT_ID,
    )

    with patch_aws_scanners(
        scanners,
        services,
        fake_session,
        fake_provider,
    ):
        result = run_aws_scan(
            role_arn=ROLE_ARN,
            external_id=EXTERNAL_ID,
            region_name=REGION,
            expected_account_id=None,
        )

    assert result.findings == [
        findings["s3"],
        findings["iam"],
        findings["kms"],
        findings["ec2"],
        findings["autoscaling"],
        findings["rds"],
        findings["lambda"],
        findings["vpc"],
        findings["security_group"],
        findings["route_table"],
        findings["cloudtrail"],
        findings["sns"],
        findings["ecr"],
        findings["sqs"],
        findings["stepfunctions"],
        findings["eventbridge"],
        findings["opensearch"],
        findings["elasticache"],
        findings["dynamodb"],
        findings["ecs"],
        findings["api_gateway"],
        findings["waf"],
        findings["waf"],
        findings["eks"],
        findings["secretsmanager"],
        findings["acm"],
        findings["guardduty"],
        findings["securityhub"],
        findings["inspector"],
        findings["macie"],
        findings["kinesis"],
        findings["ses"],
        findings["ssm"],
        findings["cloudwatch"],
        findings["backup"],
        findings["efs"],
        findings["cloudfront"],
        findings["elb"],
        findings["msk"],
        findings["codebuild"],
        findings["elasticbeanstalk"],
        findings["network_firewall"],
        findings["route53"],
        findings["redshift"],
        findings["neptune"],
        findings["firehose"],
        findings["emr"],
        findings["fsx"],
        findings["glue"],
        findings["mq"],
        findings["appsync"],
        findings["athena"],
        findings["config"],
        findings["cloudformation"],
        findings["amplify"],
        findings["apprunner"],
        findings["appconfig"],
        findings["appflow"],
        findings["batch"],
        findings["dms"],
        findings["datasync"],
        findings["detective"],
        findings["documentdb"],
    ]

    assert result.errors == []


def test_run_aws_scan_isolates_scanner_failure_and_continues():
    scanners, services, findings = make_mocks()

    scanners["ec2"].scan.side_effect = PermissionError(
        "EC2 access denied"
    )

    fake_session = Mock()
    fake_provider = Mock()
    fake_provider.verify_identity.return_value = Mock(
        account_id=ACCOUNT_ID,
    )

    with patch_aws_scanners(
        scanners,
        services,
        fake_session,
        fake_provider,
    ):
        result = run_aws_scan(
            role_arn=ROLE_ARN,
            external_id=EXTERNAL_ID,
            region_name=REGION,
            expected_account_id=ACCOUNT_ID,
        )

    assert result.findings == [
        findings["s3"],
        findings["iam"],
        findings["kms"],
        findings["autoscaling"],
        findings["rds"],
        findings["lambda"],
        findings["vpc"],
        findings["security_group"],
        findings["route_table"],
        findings["cloudtrail"],
        findings["sns"],
        findings["ecr"],
        findings["sqs"],
        findings["stepfunctions"],
        findings["eventbridge"],
        findings["opensearch"],
        findings["elasticache"],
        findings["dynamodb"],
        findings["ecs"],
        findings["api_gateway"],
        findings["waf"],
        findings["waf"],
        findings["eks"],
        findings["secretsmanager"],
        findings["acm"],
        findings["guardduty"],
        findings["securityhub"],
        findings["inspector"],
        findings["macie"],
        findings["kinesis"],
        findings["ses"],
        findings["ssm"],
        findings["cloudwatch"],
        findings["backup"],
        findings["efs"],
        findings["cloudfront"],
        findings["elb"],
        findings["msk"],
        findings["codebuild"],
        findings["elasticbeanstalk"],
        findings["network_firewall"],
        findings["route53"],
        findings["redshift"],
        findings["neptune"],
        findings["firehose"],
        findings["emr"],
        findings["fsx"],
        findings["glue"],
        findings["mq"],
        findings["appsync"],
        findings["athena"],
        findings["config"],
        findings["cloudformation"],
        findings["amplify"],
        findings["apprunner"],
        findings["appconfig"],
        findings["appflow"],
        findings["batch"],
        findings["dms"],
        findings["datasync"],
        findings["detective"],
        findings["documentdb"],
    ]

    assert len(result.errors) == 1
    assert result.errors[0].service == "ec2"
    assert "EC2 access denied" in result.errors[0].message
