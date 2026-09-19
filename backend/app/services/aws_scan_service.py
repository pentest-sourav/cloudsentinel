from scanner.aws.scanners.ec2 import EC2Scanner
from scanner.aws.scanners.iam import IAMScanner
from scanner.aws.scanners.rds import RDSScanner
from scanner.aws.scanners.lambda_scanner import LambdaScanner
from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.scanners.vpc_scanner import VPCScanner
from scanner.aws.scanners.security_group_scanner import SecurityGroupScanner

from scanner.aws.services.lambda_service import LambdaService
from scanner.aws.services.ec2 import EC2Service
from scanner.aws.services.iam import IAMService
from scanner.aws.services.rds import RDSService
from scanner.aws.services.s3 import S3Service
from scanner.aws.services.vpc import VPCService
from scanner.aws.services.security_groups import SecurityGroupService

from scanner.aws.session import create_aws_session


def run_aws_scan() -> list:
    """
    Run all enabled AWS security scanners.

    The scan is read-only:
    AWS services are queried for configuration data,
    security rules analyze the collected data,
    and findings are returned for persistence.
    """

    session = create_aws_session()

    # S3
    s3_service = S3Service(session)
    s3_scanner = S3Scanner(s3_service)
    s3_findings = s3_scanner.scan()

    # IAM
    iam_service = IAMService(session)
    iam_scanner = IAMScanner(iam_service)
    iam_findings = iam_scanner.scan()

    # EC2
    ec2_service = EC2Service(session)
    ec2_scanner = EC2Scanner(ec2_service)
    ec2_findings = ec2_scanner.scan()

    # RDS
    rds_service = RDSService(session)
    rds_scanner = RDSScanner(rds_service)
    rds_findings = rds_scanner.scan()

    # Lambda
    lambda_service = LambdaService(session)
    lambda_scanner = LambdaScanner(lambda_service)
    lambda_findings = lambda_scanner.scan()

    # VPC
    vpc_service = VPCService(session)
    vpc_scanner = VPCScanner(vpc_service)
    vpc_findings = vpc_scanner.scan()

    # Security Groups
    security_group_service = SecurityGroupService(session)
    security_group_scanner = SecurityGroupScanner(security_group_service)
    security_group_findings = security_group_scanner.scan()

    return (
        s3_findings
        + iam_findings
        + ec2_findings
        + rds_findings
        + lambda_findings
        + vpc_findings
        + security_group_findings

    )
