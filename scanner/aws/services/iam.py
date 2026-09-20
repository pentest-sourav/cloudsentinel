import json
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError


class IAMService:
    def __init__(self, session):
        self.session = session
        self.iam_client = session.client("iam")

    def get_account_summary(self) -> dict[str, Any]:
        try:
            response = self.iam_client.get_account_summary()

            return response.get(
                "SummaryMap",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM account summary check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking IAM account summary: "
                f"{exc}"
            ) from exc

    def get_root_mfa_status(self) -> bool:
        summary = self.get_account_summary()

        return summary.get(
            "AccountMFAEnabled",
            0,
        ) == 1

    def list_users(self) -> list[dict[str, Any]]:
        try:
            response = self.iam_client.list_users()

            return response.get(
                "Users",
                [],
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM user listing failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing IAM users: "
                f"{exc}"
            ) from exc

    def list_mfa_devices(
        self,
        username: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.iam_client.list_mfa_devices(
                UserName=username,
            )

            return response.get(
                "MFADevices",
                [],
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM MFA device check failed for user "
                f"'{username}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking MFA devices "
                f"for user '{username}': {exc}"
            ) from exc

    def list_access_keys(
        self,
        username: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.iam_client.list_access_keys(
                UserName=username,
            )

            return response.get(
                "AccessKeyMetadata",
                [],
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM access key listing failed for user "
                f"'{username}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing access keys "
                f"for user '{username}': {exc}"
            ) from exc

    def get_account_password_policy(self) -> dict[str, Any]:
        try:
            response = self.iam_client.get_account_password_policy()

            return response.get(
                "PasswordPolicy",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM password policy check failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking IAM password policy: "
                f"{exc}"
            ) from exc

    def generate_credential_report(self) -> dict[str, Any]:
        try:
            response = self.iam_client.generate_credential_report()

            return response

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM credential report generation failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while generating IAM credential report: "
                f"{exc}"
            ) from exc

    def get_credential_report(self) -> dict[str, Any]:
        try:
            response = self.iam_client.get_credential_report()

            return response

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM credential report retrieval failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving IAM credential report: "
                f"{exc}"
            ) from exc

    def list_attached_user_policies(
        self,
        username: str,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.iam_client.get_paginator(
                "list_attached_user_policies"
            )

            policies: list[dict[str, Any]] = []

            for page in paginator.paginate(
                UserName=username,
            ):
                policies.extend(
                    page.get(
                        "AttachedPolicies",
                        [],
                    )
                )

            return policies

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM attached policy listing failed for user "
                f"'{username}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing attached policies "
                f"for user '{username}': {exc}"
            ) from exc

    def list_groups_for_user(
        self,
        username: str,
    ) -> list[dict[str, Any]]:
        """
        Return all IAM groups that the specified user belongs to.

        IAM can paginate group membership results, so the service
        consumes the paginator and returns one normalized list for
        callers.
        """
        try:
            paginator = self.iam_client.get_paginator(
                "list_groups_for_user"
            )

            groups: list[dict[str, Any]] = []

            for page in paginator.paginate(
                UserName=username,
            ):
                groups.extend(
                    page.get(
                        "Groups",
                        [],
                    )
                )

            return groups

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM group listing failed for user "
                f"'{username}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing groups "
                f"for user '{username}': {exc}"
            ) from exc

    def list_attached_group_policies(
        self,
        group_name: str,
    ) -> list[dict[str, Any]]:
        """
        Return all managed policies directly attached to an IAM group.

        Only managed policies are returned by this method. Inline group
        policies are intentionally handled separately so the service
        layer preserves the distinction between managed and inline
        policy sources.
        """
        try:
            paginator = self.iam_client.get_paginator(
                "list_attached_group_policies"
            )

            policies: list[dict[str, Any]] = []

            for page in paginator.paginate(
                GroupName=group_name,
            ):
                policies.extend(
                    page.get(
                        "AttachedPolicies",
                        [],
                    )
                )

            return policies

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM attached group policy listing failed for "
                f"group '{group_name}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing attached group policies "
                f"for group '{group_name}': {exc}"
            ) from exc

    def get_policy(
        self,
        policy_arn: str,
    ) -> dict[str, Any]:
        try:
            response = self.iam_client.get_policy(
                PolicyArn=policy_arn,
            )

            return response.get(
                "Policy",
                {},
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM policy retrieval failed for "
                f"'{policy_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving IAM policy "
                f"'{policy_arn}': {exc}"
            ) from exc

    def get_policy_version(
        self,
        policy_arn: str,
        version_id: str,
    ) -> dict[str, Any]:
        try:
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )

            version = response.get(
                "PolicyVersion",
                {},
            )

            document = version.get(
                "Document",
                {},
            )

            if isinstance(document, str):
                document = json.loads(
                    unquote(document)
                )

            return {
                "policy_version": version,
                "document": document,
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM policy version retrieval failed for "
                f"'{policy_arn}' version '{version_id}': "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving IAM policy version "
                f"'{policy_arn}' version '{version_id}': {exc}"
            ) from exc
