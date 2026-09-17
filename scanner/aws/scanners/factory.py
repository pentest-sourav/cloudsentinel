from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.services.s3 import S3Service
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
