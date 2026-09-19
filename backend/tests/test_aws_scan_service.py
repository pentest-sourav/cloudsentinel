from unittest.mock import Mock, patch

from backend.app.services.aws_scan_service import run_aws_scan


def test_run_aws_scan_includes_route_table_findings():
    route_table_finding = Mock()
    route_table_finding.rule_id = "CS-AWS-RT-001"

    with (
        patch(
            "backend.app.services.aws_scan_service.create_aws_session"
        ) as mock_session,
        patch(
            "backend.app.services.aws_scan_service.S3Scanner"
        ) as mock_s3_scanner,
        patch(
            "backend.app.services.aws_scan_service.IAMScanner"
        ) as mock_iam_scanner,
        patch(
            "backend.app.services.aws_scan_service.EC2Scanner"
        ) as mock_ec2_scanner,
        patch(
            "backend.app.services.aws_scan_service.RDSScanner"
        ) as mock_rds_scanner,
        patch(
            "backend.app.services.aws_scan_service.LambdaScanner"
        ) as mock_lambda_scanner,
        patch(
            "backend.app.services.aws_scan_service.VPCScanner"
        ) as mock_vpc_scanner,
        patch(
            "backend.app.services.aws_scan_service.SecurityGroupScanner"
        ) as mock_security_group_scanner,
        patch(
            "backend.app.services.aws_scan_service.RouteTableScanner"
        ) as mock_route_table_scanner,
    ):
        session = Mock()
        mock_session.return_value = session

        mock_s3_scanner.return_value.scan.return_value = []
        mock_iam_scanner.return_value.scan.return_value = []
        mock_ec2_scanner.return_value.scan.return_value = []
        mock_rds_scanner.return_value.scan.return_value = []
        mock_lambda_scanner.return_value.scan.return_value = []
        mock_vpc_scanner.return_value.scan.return_value = []
        mock_security_group_scanner.return_value.scan.return_value = [
            Mock(rule_id="CS-AWS-SG-001")
        ]
        mock_route_table_scanner.return_value.scan.return_value = [
            route_table_finding
        ]

        findings = run_aws_scan()

    assert len(findings) == 2

    rule_ids = [finding.rule_id for finding in findings]

    assert "CS-AWS-SG-001" in rule_ids
    assert "CS-AWS-RT-001" in rule_ids

    mock_route_table_scanner.return_value.scan.assert_called_once()
