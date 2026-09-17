from unittest.mock import Mock, patch

from backend.app.services.aws_scan_service import run_aws_scan


def test_run_aws_scan_combines_s3_and_iam_findings():
    s3_finding = Mock(rule_id="CS-AWS-S3-001")
    iam_finding = Mock(rule_id="CS-AWS-IAM-001")

    mock_s3_scanner = Mock()
    mock_s3_scanner.scan.return_value = [s3_finding]

    mock_iam_scanner = Mock()
    mock_iam_scanner.scan.return_value = [iam_finding]

    mock_s3_service = Mock()
    mock_iam_service = Mock()

    with patch(
        "backend.app.services.aws_scan_service.create_aws_session"
    ) as mock_session, patch(
        "backend.app.services.aws_scan_service.S3Service",
        return_value=mock_s3_service,
    ), patch(
        "backend.app.services.aws_scan_service.S3Scanner",
        return_value=mock_s3_scanner,
    ), patch(
        "backend.app.services.aws_scan_service.IAMService",
        return_value=mock_iam_service,
    ), patch(
        "backend.app.services.aws_scan_service.IAMScanner",
        return_value=mock_iam_scanner,
    ):
        result = run_aws_scan()

    assert result == [
        s3_finding,
        iam_finding,
    ]

    mock_session.assert_called_once()
    mock_s3_scanner.scan.assert_called_once()
    mock_iam_scanner.scan.assert_called_once()
