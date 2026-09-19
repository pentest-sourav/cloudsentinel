from unittest.mock import Mock

from scanner.aws.services.iam import IAMService


def test_list_access_keys_returns_access_key_metadata():
    session = Mock()
    iam_client = Mock()

    iam_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "UserName": "cloudsentinel-auditor",
                "AccessKeyId": "AKIAEXAMPLE123",
                "Status": "Active",
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        ]
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_access_keys(
        "cloudsentinel-auditor"
    )

    assert result == [
        {
            "UserName": "cloudsentinel-auditor",
            "AccessKeyId": "AKIAEXAMPLE123",
            "Status": "Active",
            "CreateDate": "2026-01-01T00:00:00Z",
        }
    ]

    iam_client.list_access_keys.assert_called_once_with(
        UserName="cloudsentinel-auditor"
    )
