from unittest.mock import Mock, patch

from scanner.aws.scanners.factory import create_s3_scanner
from scanner.aws.scanners.s3 import S3Scanner
from scanner.aws.services.s3 import S3Service


def test_create_s3_scanner():
    fake_session = Mock()

    with patch(
        "scanner.aws.scanners.factory.create_aws_session",
        return_value=fake_session,
    ) as mock_create_session:
        scanner = create_s3_scanner(
            profile_name="cloudsentinel",
            region_name="ap-south-1",
        )

    assert isinstance(scanner, S3Scanner)
    assert isinstance(scanner.collector, object)
    assert isinstance(scanner.collector.service, S3Service)

    assert scanner.collector.service.session is fake_session

    mock_create_session.assert_called_once_with(
        profile_name="cloudsentinel",
        region_name="ap-south-1",
    )
