from scanner.aws.scanners.iam import IAMScanner
from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.services.iam import IAMService
from scanner.aws.services.s3 import S3Service
from scanner.aws.session import create_aws_session


def run_aws_scan() -> list:
    session = create_aws_session()

    # S3 security audit
    s3_service = S3Service(session)
    s3_scanner = S3Scanner(s3_service)
    s3_findings = s3_scanner.scan()

    # IAM security audit
    iam_service = IAMService(session)
    iam_scanner = IAMScanner(iam_service)
    iam_findings = iam_scanner.scan()

    # Combine findings from all AWS scanners
    return s3_findings + iam_findings
