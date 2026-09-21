from unittest.mock import Mock

from scanner.aws.collectors.iam import IAMDataCollector


def _build_collector():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "UserManagedPolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/UserManagedPolicy"
            ),
        },
    ]

    service.get_policy.return_value = {
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "document": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::company-data/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalTag/Environment": "prod",
                        }
                    },
                },
            ]
        }
    }

    service.list_groups_for_user.return_value = [
        {"GroupName": "Developers"},
    ]

    service.list_attached_group_policies.return_value = [
        {
            "PolicyName": "GroupManagedPolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "GroupManagedPolicy"
            ),
        },
    ]

    service.list_user_policies.return_value = [
        "UserInlinePolicy",
    ]

    service.get_user_policy.return_value = {
        "document": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "arn:aws:dynamodb:"
                    "eu-north-1:123456789012:"
                    "table/CustomerData",
                },
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::blocked/*",
                },
            ]
        }
    }

    service.list_groups.return_value = [
        {"GroupName": "Developers"},
        {"GroupName": "OrphanGroup"},
    ]

    service.list_group_policies.side_effect = [
        ["GroupInlinePolicy"],
        ["OrphanInlinePolicy"],
    ]

    service.get_group_policy.side_effect = [
        {
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": [
                            "arn:aws:s3:::developer-data",
                            "arn:aws:s3:::developer-data/*",
                        ],
                    },
                ]
            }
        },
        {
            "document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DescribeInstances",
                            "*",
                        ],
                        "Resource": (
                            "arn:aws:ec2:eu-north-1:"
                            "123456789012:instance/i-1234567890"
                        ),
                    },
                ]
            }
        },
    ]

    collector = IAMDataCollector(service)

    return collector, service


def test_combined_collector_normalizes_all_four_permission_sources():
    collector, _ = _build_collector()

    findings_data = (
        collector.collect_broad_action_restricted_resources()
    )

    assert len(findings_data) == 6

    permission_sources = [
        item["permission_source"]
        for item in findings_data
    ]

    assert permission_sources == [
        "user_managed_policy",
        "group_managed_policy",
        "user_inline_policy",
        "user_inline_policy",
        "group_inline_policy",
        "group_inline_policy",
    ]


def test_user_managed_policy_is_normalized_correctly():
    collector, _ = _build_collector()

    findings_data = (
        collector.collect_broad_action_restricted_resources()
    )

    result = findings_data[0]

    assert result == {
        "permission_source": "user_managed_policy",
        "resource_id": "alice",
        "principal_type": "user",
        "principal_id": "alice",
        "username": "alice",
        "group_name": None,
        "policy_name": "UserManagedPolicy",
        "policy_arn": (
            "arn:aws:iam::123456789012:policy/"
            "UserManagedPolicy"
        ),
        "policy_version_id": "v1",
        "statement_index": None,
        "effect": "Allow",
        "action": "*",
        "resource": "arn:aws:s3:::company-data/*",
        "condition": {
            "StringEquals": {
                "aws:PrincipalTag/Environment": "prod",
            }
        },
    }


def test_group_managed_policy_is_normalized_correctly():
    collector, _ = _build_collector()

    findings_data = (
        collector.collect_broad_action_restricted_resources()
    )

    result = findings_data[1]

    assert result["permission_source"] == (
        "group_managed_policy"
    )
    assert result["resource_id"] == "Developers"
    assert result["principal_type"] == "group"
    assert result["principal_id"] == "Developers"
    assert result["username"] == "alice"
    assert result["group_name"] == "Developers"
    assert result["policy_name"] == "GroupManagedPolicy"
    assert result["policy_arn"] == (
        "arn:aws:iam::123456789012:policy/"
        "GroupManagedPolicy"
    )
    assert result["policy_version_id"] == "v1"
    assert result["statement_index"] is None
    assert result["effect"] == "Allow"
    assert result["action"] == "*"


def test_user_inline_policy_preserves_statement_index():
    collector, _ = _build_collector()

    findings_data = (
        collector.collect_broad_action_restricted_resources()
    )

    first_inline = findings_data[2]
    second_inline = findings_data[3]

    assert first_inline["permission_source"] == (
        "user_inline_policy"
    )
    assert first_inline["principal_type"] == "user"
    assert first_inline["principal_id"] == "alice"
    assert first_inline["username"] == "alice"
    assert first_inline["group_name"] is None
    assert first_inline["policy_name"] == "UserInlinePolicy"
    assert first_inline["policy_arn"] is None
    assert first_inline["policy_version_id"] is None
    assert first_inline["statement_index"] == 0

    assert second_inline["permission_source"] == (
        "user_inline_policy"
    )
    assert second_inline["statement_index"] == 1
    assert second_inline["effect"] == "Deny"


def test_group_inline_policy_preserves_group_metadata():
    collector, _ = _build_collector()

    findings_data = (
        collector.collect_broad_action_restricted_resources()
    )

    result = findings_data[4]

    assert result["permission_source"] == (
        "group_inline_policy"
    )
    assert result["resource_id"] == "Developers"
    assert result["principal_type"] == "group"
    assert result["principal_id"] == "Developers"
    assert result["username"] is None
    assert result["group_name"] == "Developers"
    assert result["policy_name"] == "GroupInlinePolicy"
    assert result["statement_index"] == 0
    assert result["action"] == "*"
    assert result["resource"] == [
        "arn:aws:s3:::developer-data",
        "arn:aws:s3:::developer-data/*",
    ]


def test_orphan_group_inline_policy_is_collected():
    collector, _ = _build_collector()

    findings_data = (
        collector.collect_broad_action_restricted_resources()
    )

    result = findings_data[5]

    assert result["permission_source"] == (
        "group_inline_policy"
    )
    assert result["resource_id"] == "OrphanGroup"
    assert result["principal_type"] == "group"
    assert result["principal_id"] == "OrphanGroup"
    assert result["username"] is None
    assert result["group_name"] == "OrphanGroup"
    assert result["policy_name"] == "OrphanInlinePolicy"
    assert result["statement_index"] == 0
    assert result["action"] == [
        "ec2:DescribeInstances",
        "*",
    ]


def test_combined_collector_uses_cache_on_second_call():
    collector, service = _build_collector()

    first_result = (
        collector.collect_broad_action_restricted_resources()
    )

    service.list_users.reset_mock()
    service.list_attached_user_policies.reset_mock()
    service.get_policy.reset_mock()
    service.get_policy_version.reset_mock()
    service.list_groups_for_user.reset_mock()
    service.list_attached_group_policies.reset_mock()
    service.list_user_policies.reset_mock()
    service.get_user_policy.reset_mock()
    service.list_groups.reset_mock()
    service.list_group_policies.reset_mock()
    service.get_group_policy.reset_mock()

    second_result = (
        collector.collect_broad_action_restricted_resources()
    )

    assert second_result == first_result

    service.list_users.assert_not_called()
    service.list_attached_user_policies.assert_not_called()
    service.get_policy.assert_not_called()
    service.get_policy_version.assert_not_called()
    service.list_groups_for_user.assert_not_called()
    service.list_attached_group_policies.assert_not_called()
    service.list_user_policies.assert_not_called()
    service.get_user_policy.assert_not_called()
    service.list_groups.assert_not_called()
    service.list_group_policies.assert_not_called()
    service.get_group_policy.assert_not_called()
