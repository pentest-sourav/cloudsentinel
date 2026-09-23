from unittest.mock import MagicMock

from scanner.aws.collectors.iam import IAMDataCollector


def test_access_analyzer_security_warning_is_collected():
    service = MagicMock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]
    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "CustomPolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/CustomPolicy"
            ),
        }
    ]
    service.get_policy.return_value = {
        "Arn": (
            "arn:aws:iam::123456789012:policy/CustomPolicy"
        ),
        "DefaultVersionId": "v1",
    }
    service.get_policy_version.return_value = {
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                }
            ],
        }
    }

    service.list_user_policies.return_value = []
    service.list_groups.return_value = []
    service.list_roles.return_value = []

    service.validate_policy.return_value = [
        {
            "findingType": "SECURITY_WARNING",
            "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
            "findingDetails": "Overly broad PassRole.",
            "learnMoreLink": "https://example.com",
            "locations": [],
        },
        {
            "findingType": "SUGGESTION",
            "issueCode": "STYLE",
            "findingDetails": "Suggestion.",
            "learnMoreLink": "https://example.com",
            "locations": [],
        },
    ]

    collector = IAMDataCollector(service)

    findings = collector.collect_access_analyzer_policy_validation()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "SECURITY_WARNING"
    assert findings[0]["issue_code"] == (
        "PASS_ROLE_WITH_STAR_IN_RESOURCE"
    )
    assert findings[0]["permission_source"] == (
        "user_managed_policy"
    )

    service.validate_policy.assert_called_once()


def test_access_analyzer_skips_aws_managed_policy():
    service = MagicMock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]
    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": (
                "arn:aws:iam::aws:policy/AdministratorAccess"
            ),
        }
    ]
    service.list_groups.return_value = []
    service.list_roles.return_value = []
    service.list_user_policies.return_value = []

    collector = IAMDataCollector(service)

    findings = collector.collect_access_analyzer_policy_validation()

    assert findings == []
    service.validate_policy.assert_not_called()


def test_access_analyzer_deduplicates_customer_managed_policy():
    service = MagicMock()

    policy_arn = (
        "arn:aws:iam::123456789012:policy/SharedPolicy"
    )

    service.list_users.return_value = [
        {"UserName": "alice"},
        {"UserName": "bob"},
    ]

    service.list_attached_user_policies.side_effect = [
        [
            {
                "PolicyName": "SharedPolicy",
                "PolicyArn": policy_arn,
            }
        ],
        [
            {
                "PolicyName": "SharedPolicy",
                "PolicyArn": policy_arn,
            }
        ],
    ]

    service.get_policy.return_value = {
        "Arn": policy_arn,
        "DefaultVersionId": "v1",
    }
    service.get_policy_version.return_value = {
        "document": {
            "Version": "2012-10-17",
            "Statement": [],
        }
    }

    service.list_user_policies.return_value = []
    service.list_groups.return_value = []
    service.list_roles.return_value = []

    service.validate_policy.return_value = []

    collector = IAMDataCollector(service)

    collector.collect_access_analyzer_policy_validation()

    service.validate_policy.assert_called_once()
