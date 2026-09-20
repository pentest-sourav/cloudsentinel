from unittest.mock import Mock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

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


def test_get_account_password_policy_returns_password_policy():
    session = Mock()
    iam_client = Mock()
    iam_client.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "AllowUsersToChangePassword": True,
            "ExpirePasswords": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_account_password_policy()

    assert result == {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
    }

    iam_client.get_account_password_policy.assert_called_once_with()


def test_generate_credential_report_returns_report_metadata():
    session = Mock()
    iam_client = Mock()

    iam_client.generate_credential_report.return_value = {
        "State": "COMPLETE",
        "Description": "Report generated successfully",
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.generate_credential_report()

    assert result == {
        "State": "COMPLETE",
        "Description": "Report generated successfully",
    }

    iam_client.generate_credential_report.assert_called_once_with()


def test_get_credential_report_returns_report():
    session = Mock()
    iam_client = Mock()

    iam_client.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"alice,true,2026-01-01T00:00:00+00:00\n"
        ),
        "ReportFormat": "text/csv",
        "GeneratedTime": "2026-09-20T00:00:00Z",
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_credential_report()

    assert result == {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"alice,true,2026-01-01T00:00:00+00:00\n"
        ),
        "ReportFormat": "text/csv",
        "GeneratedTime": "2026-09-20T00:00:00Z",
    }

    iam_client.get_credential_report.assert_called_once_with()


def test_list_attached_user_policies_returns_attached_policies():
    session = Mock()
    iam_client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdminLikePolicy",
                    "PolicyArn": (
                        "arn:aws:iam::123456789012:policy/"
                        "AdminLikePolicy"
                    ),
                }
            ]
        },
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "ReadOnlyPolicy",
                    "PolicyArn": (
                        "arn:aws:iam::123456789012:policy/"
                        "ReadOnlyPolicy"
                    ),
                }
            ]
        },
    ]

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_attached_user_policies(
        "alice"
    )

    assert result == [
        {
            "PolicyName": "AdminLikePolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "AdminLikePolicy"
            ),
        },
        {
            "PolicyName": "ReadOnlyPolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "ReadOnlyPolicy"
            ),
        },
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_attached_user_policies"
    )

    paginator.paginate.assert_called_once_with(
        UserName="alice"
    )


def test_list_user_policies_returns_all_inline_policy_names():
    session = Mock()
    iam_client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "PolicyNames": [
                "DeveloperInlinePolicy",
            ]
        },
        {
            "PolicyNames": [
                "SecurityInlinePolicy",
                "AuditInlinePolicy",
            ]
        },
    ]

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_user_policies("alice")

    assert result == [
        "DeveloperInlinePolicy",
        "SecurityInlinePolicy",
        "AuditInlinePolicy",
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_user_policies"
    )

    paginator.paginate.assert_called_once_with(
        UserName="alice"
    )


def test_get_user_policy_returns_decoded_policy_document():
    session = Mock()
    iam_client = Mock()

    iam_client.get_user_policy.return_value = {
        "UserName": "alice",
        "PolicyName": "DeveloperInlinePolicy",
        "PolicyDocument": (
            "%7B%22Version%22%3A%222012-10-17%22%2C"
            "%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C"
            "%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%7D"
        ),
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_user_policy(
        "alice",
        "DeveloperInlinePolicy",
    )

    assert result == {
        "policy_name": "DeveloperInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    iam_client.get_user_policy.assert_called_once_with(
        UserName="alice",
        PolicyName="DeveloperInlinePolicy",
    )


def test_list_groups_for_user_returns_all_groups():
    session = Mock()
    iam_client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "Groups": [
                {
                    "GroupName": "Developers",
                    "GroupId": "AGPAEXAMPLE1",
                    "Arn": (
                        "arn:aws:iam::123456789012:group/"
                        "Developers"
                    ),
                }
            ]
        },
        {
            "Groups": [
                {
                    "GroupName": "Security",
                    "GroupId": "AGPAEXAMPLE2",
                    "Arn": (
                        "arn:aws:iam::123456789012:group/"
                        "Security"
                    ),
                }
            ]
        },
    ]

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_groups_for_user(
        "alice"
    )

    assert result == [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE1",
            "Arn": (
                "arn:aws:iam::123456789012:group/"
                "Developers"
            ),
        },
        {
            "GroupName": "Security",
            "GroupId": "AGPAEXAMPLE2",
            "Arn": (
                "arn:aws:iam::123456789012:group/"
                "Security"
            ),
        },
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_groups_for_user"
    )

    paginator.paginate.assert_called_once_with(
        UserName="alice"
    )


def test_list_attached_group_policies_returns_attached_policies():
    session = Mock()
    iam_client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "DeveloperAccess",
                    "PolicyArn": (
                        "arn:aws:iam::123456789012:policy/"
                        "DeveloperAccess"
                    ),
                }
            ]
        },
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "SecurityAudit",
                    "PolicyArn": (
                        "arn:aws:iam::123456789012:policy/"
                        "SecurityAudit"
                    ),
                }
            ]
        },
    ]

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_attached_group_policies(
        "Developers"
    )

    assert result == [
        {
            "PolicyName": "DeveloperAccess",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "DeveloperAccess"
            ),
        },
        {
            "PolicyName": "SecurityAudit",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "SecurityAudit"
            ),
        },
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_attached_group_policies"
    )

    paginator.paginate.assert_called_once_with(
        GroupName="Developers"
    )


def test_get_policy_returns_policy_metadata():
    session = Mock()
    iam_client = Mock()

    iam_client.get_policy.return_value = {
        "Policy": {
            "PolicyName": "AdminLikePolicy",
            "Arn": (
                "arn:aws:iam::123456789012:policy/"
                "AdminLikePolicy"
            ),
            "DefaultVersionId": "v3",
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    policy_arn = (
        "arn:aws:iam::123456789012:policy/"
        "AdminLikePolicy"
    )

    result = service.get_policy(policy_arn)

    assert result == {
        "PolicyName": "AdminLikePolicy",
        "Arn": policy_arn,
        "DefaultVersionId": "v3",
    }

    iam_client.get_policy.assert_called_once_with(
        PolicyArn=policy_arn
    )


def test_get_policy_version_returns_policy_document():
    session = Mock()
    iam_client = Mock()

    policy_arn = (
        "arn:aws:iam::123456789012:policy/"
        "AdminLikePolicy"
    )

    iam_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "VersionId": "v3",
            "IsDefaultVersion": True,
            "Document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            },
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_policy_version(
        policy_arn,
        "v3",
    )

    assert result == {
        "policy_version": {
            "VersionId": "v3",
            "IsDefaultVersion": True,
            "Document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            },
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    iam_client.get_policy_version.assert_called_once_with(
        PolicyArn=policy_arn,
        VersionId="v3",
    )


def test_get_policy_version_decodes_encoded_policy_document():
    session = Mock()
    iam_client = Mock()

    policy_arn = (
        "arn:aws:iam::123456789012:policy/"
        "EncodedPolicy"
    )

    iam_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "VersionId": "v1",
            "Document": (
                "%7B%22Version%22%3A%22"
                "2012-10-17%22%2C%22Statement%22%3A"
                "%5B%5D%7D"
            ),
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_policy_version(
        policy_arn,
        "v1",
    )

    assert result["document"] == {
        "Version": "2012-10-17",
        "Statement": [],
    }


def test_list_attached_user_policies_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized",
            }
        },
        "GetPaginator",
    )

    session.client.return_value = iam_client
    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM attached policy listing failed for user "
            "'alice': AccessDenied: User is not authorized"
        ),
    ):
        service.list_attached_user_policies("alice")


def test_list_user_policies_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized",
            }
        },
        "GetPaginator",
    )

    session.client.return_value = iam_client
    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM inline policy listing failed for user "
            "'alice': AccessDenied: User is not authorized"
        ),
    ):
        service.list_user_policies("alice")


def test_get_user_policy_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_user_policy.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchEntity",
                "Message": "Policy does not exist",
            }
        },
        "GetUserPolicy",
    )

    session.client.return_value = iam_client
    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM inline policy retrieval failed for user "
            "'alice' policy 'MissingPolicy': "
            "NoSuchEntity: Policy does not exist"
        ),
    ):
        service.get_user_policy(
            "alice",
            "MissingPolicy",
        )


def test_get_policy_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_policy.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchEntity",
                "Message": "Policy does not exist",
            }
        },
        "GetPolicy",
    )

    session.client.return_value = iam_client

    service = IAMService(session)

    policy_arn = (
        "arn:aws:iam::123456789012:policy/"
        "MissingPolicy"
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM policy retrieval failed for "
            f"'{policy_arn}': NoSuchEntity: Policy does not exist"
        ),
    ):
        service.get_policy(policy_arn)


def test_get_policy_version_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_policy_version.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchEntity",
                "Message": "Policy version does not exist",
            }
        },
        "GetPolicyVersion",
    )

    session.client.return_value = iam_client

    service = IAMService(session)

    policy_arn = (
        "arn:aws:iam::123456789012:policy/"
        "MissingPolicy"
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM policy version retrieval failed for "
            f"'{policy_arn}' version 'v9': "
            "NoSuchEntity: Policy version does not exist"
        ),
    ):
        service.get_policy_version(
            policy_arn,
            "v9",
        )


def test_list_attached_user_policies_wraps_botocore_error():
    session = Mock()
    iam_client = Mock()

    paginator = Mock()
    paginator.paginate.side_effect = BotoCoreError()

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "AWS SDK error while listing attached policies "
            "for user 'alice'"
        ),
    ):
        service.list_attached_user_policies("alice")


def test_list_user_policies_wraps_botocore_error():
    session = Mock()
    iam_client = Mock()

    paginator = Mock()
    paginator.paginate.side_effect = BotoCoreError()

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "AWS SDK error while listing inline policies "
            "for user 'alice'"
        ),
    ):
        service.list_user_policies("alice")


def test_get_user_policy_wraps_botocore_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_user_policy.side_effect = BotoCoreError()

    session.client.return_value = iam_client

    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "AWS SDK error while retrieving inline policy "
            "'MissingPolicy' for user 'alice'"
        ),
    ):
        service.get_user_policy(
            "alice",
            "MissingPolicy",
        )


def test_list_groups_for_user_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized",
            }
        },
        "GetPaginator",
    )

    session.client.return_value = iam_client
    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM group listing failed for user "
            "'alice': AccessDenied: User is not authorized"
        ),
    ):
        service.list_groups_for_user("alice")


def test_list_attached_group_policies_wraps_client_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Group policy access denied",
            }
        },
        "GetPaginator",
    )

    session.client.return_value = iam_client
    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "IAM attached group policy listing failed for "
            "group 'Developers': AccessDenied: "
            "Group policy access denied"
        ),
    ):
        service.list_attached_group_policies(
            "Developers"
        )


def test_get_user_policy_wraps_malformed_json_error():
    session = Mock()
    iam_client = Mock()

    iam_client.get_user_policy.return_value = {
        "PolicyName": "BrokenPolicy",
        "PolicyDocument": "%7B%22Version%22%3A",
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    with pytest.raises(
        ValueError,
    ):
        service.get_user_policy(
            "alice",
            "BrokenPolicy",
        )


def test_list_attached_group_policies_wraps_botocore_error():
    session = Mock()
    iam_client = Mock()

    paginator = Mock()
    paginator.paginate.side_effect = BotoCoreError()

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "AWS SDK error while listing attached group policies "
            "for group 'Developers'"
        ),
    ):
        service.list_attached_group_policies(
            "Developers"
        )


def test_list_groups_for_user_wraps_botocore_error():
    session = Mock()
    iam_client = Mock()

    paginator = Mock()
    paginator.paginate.side_effect = BotoCoreError()

    iam_client.get_paginator.return_value = paginator
    session.client.return_value = iam_client

    service = IAMService(session)

    with pytest.raises(
        RuntimeError,
        match=(
            "AWS SDK error while listing groups "
            "for user 'alice'"
        ),
    ):
        service.list_groups_for_user("alice")
