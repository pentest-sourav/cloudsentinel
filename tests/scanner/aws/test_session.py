from unittest.mock import patch

from scanner.aws.session import create_aws_session


def test_create_aws_session():
    with patch("scanner.aws.session.boto3.Session") as mock_session:
        create_aws_session(
            profile_name="cloudsentinel",
            region_name="ap-south-1",
        )

        mock_session.assert_called_once_with(
            profile_name="cloudsentinel",
            region_name="ap-south-1",
        )
