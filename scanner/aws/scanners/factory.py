from scanner.aws.scanners.kms import KMSScanner
from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.scanners.vpc_scanner import VPCScanner
from scanner.aws.services.kms import KMSService
from scanner.aws.services.s3 import S3Service
from scanner.aws.services.vpc import VPCService
from scanner.aws.session import create_aws_session


def create_s3_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> S3Scanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = S3Service(session)

    return S3Scanner(service)


def create_kms_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> KMSScanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = KMSService(session)

    return KMSScanner(service)


def create_vpc_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> VPCScanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = VPCService(session)

    return VPCScanner(service)
