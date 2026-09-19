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

def test_run_aws_scan_includes_ec2_findings():
    s3_finding = Mock(rule_id="CS-AWS-S3-001")
    iam_finding = Mock(rule_id="CS-AWS-IAM-001")
    ec2_finding = Mock(rule_id="CS-AWS-EC2-001")

    mock_s3_scanner = Mock()
    mock_s3_scanner.scan.return_value = [s3_finding]

    mock_iam_scanner = Mock()
    mock_iam_scanner.scan.return_value = [iam_finding]

    mock_ec2_scanner = Mock()
    mock_ec2_scanner.scan.return_value = [ec2_finding]

    mock_s3_service = Mock()
    mock_iam_service = Mock()
    mock_ec2_service = Mock()

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
    ), patch(
        "backend.app.services.aws_scan_service.EC2Service",
        return_value=mock_ec2_service,
    ), patch(
        "backend.app.services.aws_scan_service.EC2Scanner",
        return_value=mock_ec2_scanner,
    ):
        result = run_aws_scan()

    assert result == [
        s3_finding,
        iam_finding,
        ec2_finding,
    ]

    mock_session.assert_called_once()
    mock_s3_scanner.scan.assert_called_once()
    mock_iam_scanner.scan.assert_called_once()
    mock_ec2_scanner.scan.assert_called_once()
def test_run_aws_scan_includes_lambda_findings():
    s3_finding = Mock(rule_id="CS-AWS-S3-001")
    iam_finding = Mock(rule_id="CS-AWS-IAM-001")
    ec2_finding = Mock(rule_id="CS-AWS-EC2-001")
    rds_finding = Mock(rule_id="CS-AWS-RDS-001")
    lambda_finding = Mock(rule_id="CS-AWS-LAMBDA-001")

    mock_s3_scanner = Mock()
    mock_s3_scanner.scan.return_value = [s3_finding]

    mock_iam_scanner = Mock()
    mock_iam_scanner.scan.return_value = [iam_finding]

    mock_ec2_scanner = Mock()
    mock_ec2_scanner.scan.return_value = [ec2_finding]

    mock_rds_scanner = Mock()
    mock_rds_scanner.scan.return_value = [rds_finding]

    mock_lambda_scanner = Mock()
    mock_lambda_scanner.scan.return_value = [lambda_finding]

    mock_s3_service = Mock()
    mock_iam_service = Mock()
    mock_ec2_service = Mock()
    mock_rds_service = Mock()
    mock_lambda_service = Mock()

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
    ), patch(
        "backend.app.services.aws_scan_service.EC2Service",
        return_value=mock_ec2_service,
    ), patch(
        "backend.app.services.aws_scan_service.EC2Scanner",
        return_value=mock_ec2_scanner,
    ), patch(
        "backend.app.services.aws_scan_service.RDSService",
        return_value=mock_rds_service,
    ), patch(
        "backend.app.services.aws_scan_service.RDSScanner",
        return_value=mock_rds_scanner,
    ), patch(
        "backend.app.services.aws_scan_service.LambdaService",
        return_value=mock_lambda_service,
    ), patch(
        "backend.app.services.aws_scan_service.LambdaScanner",
        return_value=mock_lambda_scanner,
    ):
        result = run_aws_scan()

    assert result == [
        s3_finding,
        iam_finding,
        ec2_finding,
        rds_finding,
        lambda_finding,
    ]

    mock_session.assert_called_once()
    mock_s3_scanner.scan.assert_called_once()
    mock_iam_scanner.scan.assert_called_once()
    mock_ec2_scanner.scan.assert_called_once()
    mock_rds_scanner.scan.assert_called_once()
    mock_lambda_scanner.scan.assert_called_once()
def test_run_aws_scan_includes_vpc_findings():
    s3_finding = Mock(rule_id="CS-AWS-S3-001")
    iam_finding = Mock(rule_id="CS-AWS-IAM-001")
    ec2_finding = Mock(rule_id="CS-AWS-EC2-001")
    rds_finding = Mock(rule_id="CS-AWS-RDS-001")
    lambda_finding = Mock(rule_id="CS-AWS-LAMBDA-001")
    vpc_finding = Mock(rule_id="CS-AWS-VPC-001")

    mock_s3_scanner = Mock()
    mock_s3_scanner.scan.return_value = [s3_finding]

    mock_iam_scanner = Mock()
    mock_iam_scanner.scan.return_value = [iam_finding]

    mock_ec2_scanner = Mock()
    mock_ec2_scanner.scan.return_value = [ec2_finding]

    mock_rds_scanner = Mock()
    mock_rds_scanner.scan.return_value = [rds_finding]

    mock_lambda_scanner = Mock()
    mock_lambda_scanner.scan.return_value = [lambda_finding]

    mock_vpc_scanner = Mock()
    mock_vpc_scanner.scan.return_value = [vpc_finding]

    mock_s3_service = Mock()
    mock_iam_service = Mock()
    mock_ec2_service = Mock()
    mock_rds_service = Mock()
    mock_lambda_service = Mock()
    mock_vpc_service = Mock()

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
    ), patch(
        "backend.app.services.aws_scan_service.EC2Service",
        return_value=mock_ec2_service,
    ), patch(
        "backend.app.services.aws_scan_service.EC2Scanner",
        return_value=mock_ec2_scanner,
    ), patch(
        "backend.app.services.aws_scan_service.RDSService",
        return_value=mock_rds_service,
    ), patch(
        "backend.app.services.aws_scan_service.RDSScanner",
        return_value=mock_rds_scanner,
    ), patch(
        "backend.app.services.aws_scan_service.LambdaService",
        return_value=mock_lambda_service,
    ), patch(
        "backend.app.services.aws_scan_service.LambdaScanner",
        return_value=mock_lambda_scanner,
    ), patch(
        "backend.app.services.aws_scan_service.VPCService",
        return_value=mock_vpc_service,
    ), patch(
        "backend.app.services.aws_scan_service.VPCScanner",
        return_value=mock_vpc_scanner,
    ):
        result = run_aws_scan()

    assert result == [
        s3_finding,
        iam_finding,
        ec2_finding,
        rds_finding,
        lambda_finding,
        vpc_finding,
    ]

    mock_session.assert_called_once()
    mock_s3_scanner.scan.assert_called_once()
    mock_iam_scanner.scan.assert_called_once()
    mock_ec2_scanner.scan.assert_called_once()
    mock_rds_scanner.scan.assert_called_once()
    mock_lambda_scanner.scan.assert_called_once()
    mock_vpc_scanner.scan.assert_called_once()
