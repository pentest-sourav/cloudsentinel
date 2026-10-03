from unittest.mock import Mock, patch

from backend.app.services.aws_scan_service import run_aws_scan


ROLE_ARN = "arn:aws:iam::123456789012:role/CloudSentinelAuditRole"
EXTERNAL_ID = "cloudsentinel-test-external-id"
ACCOUNT_ID = "123456789012"


class FakeScanner:
    def __init__(self, service_name, region):
        self.service_name = service_name
        self.region = region

    def scan(self):
        return [f"{self.service_name}:{self.region}"]


def test_run_aws_scan_executes_global_and_regional_services_in_each_scope():
    base_session = Mock()
    base_session.region_name = "ap-south-1"

    regional_session = Mock()
    regional_session.region_name = "eu-west-1"

    identity = Mock(account_id=ACCOUNT_ID)
    sessions = {
        "ap-south-1": base_session,
        "eu-west-1": regional_session,
    }

    build_calls = []

    def fake_build_scanners(session, identity, region_name):
        build_calls.append((session, region_name))

        return [
            (
                "s3",
                lambda: FakeScanner("s3", region_name),
            ),
            (
                "iam",
                lambda: FakeScanner("iam", region_name),
            ),
            (
                "cloudfront",
                lambda: FakeScanner("cloudfront", region_name),
            ),
            (
                "ec2",
                lambda: FakeScanner("ec2", region_name),
            ),
        ]

    def fake_create_session(*, role_arn, external_id, region_name):
        assert role_arn == ROLE_ARN
        assert external_id == EXTERNAL_ID
        return sessions[region_name]

    with patch(
        "backend.app.services.aws_scan_service.create_aws_session",
        side_effect=fake_create_session,
    ) as create_session, patch(
        "backend.app.services.aws_scan_service.AWSProvider",
    ) as provider_class, patch(
        "backend.app.services.aws_scan_service.discover_aws_regions",
        return_value=["ap-south-1", "eu-west-1"],
    ), patch(
        "backend.app.services.aws_scan_service._build_scanners",
        side_effect=fake_build_scanners,
    ):
        provider_class.return_value.verify_identity.return_value = identity

        result = run_aws_scan(
            role_arn=ROLE_ARN,
            external_id=EXTERNAL_ID,
            region_name="ap-south-1",
            expected_account_id=ACCOUNT_ID,
        )

    assert result.errors == []

    assert result.findings == [
        "s3:ap-south-1",
        "iam:ap-south-1",
        "cloudfront:ap-south-1",
        "ec2:ap-south-1",
        "ec2:eu-west-1",
    ]

    assert build_calls == [
        (base_session, "ap-south-1"),
        (regional_session, "eu-west-1"),
    ]

    create_session.assert_called_once_with(
        role_arn=ROLE_ARN,
        external_id=EXTERNAL_ID,
        region_name="eu-west-1",
    )
