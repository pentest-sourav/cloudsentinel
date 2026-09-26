from scanner.aws.scanners.amplify import AmplifyScanner
from scanner.aws.scanners.apprunner import AppRunnerScanner
from scanner.aws.scanners.appconfig import AppConfigScanner
from scanner.aws.services.apprunner import AppRunnerService
from scanner.aws.services.amplify import AmplifyService
from scanner.aws.services.appconfig import AppConfigService
from scanner.aws.scanners.kms import KMSScanner
from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.scanners.sns import SNSScanner
from scanner.aws.scanners.vpc_scanner import VPCScanner
from scanner.aws.services.kms import KMSService
from scanner.aws.services.s3 import S3Service
from scanner.aws.services.sns import SNSService
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


def create_sns_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> SNSScanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = SNSService(
        session,
        region_name=session.region_name,
    )

    return SNSScanner(service)


def create_amplify_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> AmplifyScanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = AmplifyService(session)

    return AmplifyScanner(service)


def create_apprunner_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> AppRunnerScanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = AppRunnerService(session)

    return AppRunnerScanner(service)


def create_appconfig_scanner(
    profile_name: str | None = None,
    region_name: str | None = None,
    account_id: str | None = None,
) -> AppConfigScanner:
    session = create_aws_session(
        profile_name=profile_name,
        region_name=region_name,
    )

    service = AppConfigService(
        session,
        account_id=account_id,
        region_name=region_name or session.region_name,
    )

    return AppConfigScanner(service)
