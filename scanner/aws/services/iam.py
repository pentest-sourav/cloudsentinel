import json
from datetime import datetime
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError


class IAMService:
    def __init__(self, session):
        self.session = session
        self.iam_client = session.client("iam")
        self._account_summary_cache: dict[str, Any] | None = None
        self._attached_user_policies_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}
        self._user_inline_policies_cache: dict[
            str,
            list[str],
        ] = {}

    def get_account_summary(self) -> dict[str, Any]:
        """
        Return the IAM account summary using a per-service cache.

        Root-level IAM controls such as root MFA and root access-key
        detection share the same AWS GetAccountSummary response.
        This prevents duplicate API calls during a scan.
        """
        if self._account_summary_cache is not None:
            return self._account_summary_cache

        try:
            response = self.iam_client.get_account_summary()

            self._account_summary_cache = response.get(
                "SummaryMap",
                {},
            )

            return self._account_summary_cache

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

    def get_root_access_keys_present(self) -> bool:
        """
        Return whether the AWS account has root-user access keys.

        AWS exposes this account-level state through GetAccountSummary.
        The account summary is cached so this check can reuse the same
        API response as the root MFA check.
        """
        summary = self.get_account_summary()

        return summary.get(
            "AccountAccessKeysPresent",
            0,
        ) > 0

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

    def get_access_key_last_used(
        self,
        access_key_id: str,
    ) -> datetime | None:
        try:
            response = self.iam_client.get_access_key_last_used(
                AccessKeyId=access_key_id,
            )

            last_used = response.get(
                "AccessKeyLastUsed",
                {},
            )

            return last_used.get(
                "LastUsedDate",
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM access key last-used lookup failed for "
                f"'{access_key_id}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while checking last-used status "
                f"for access key '{access_key_id}': {exc}"
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
        """
        Return managed policies directly attached to an IAM user.

        Results are cached per username for the lifetime of this
        IAMService instance so multiple IAM rules can reuse the
        same AWS API response during one scan.
        """
        if username in self._attached_user_policies_cache:
            return self._attached_user_policies_cache[
                username
            ]

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

            self._attached_user_policies_cache[
                username
            ] = policies

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

    def list_user_policies(
        self,
        username: str,
    ) -> list[str]:
        """
        Return all inline policy names directly attached to an
        IAM user.

        Results are cached per username for the lifetime of this
        IAMService instance so multiple IAM rules can reuse the
        same AWS API response during one scan.
        """
        if username in self._user_inline_policies_cache:
            return self._user_inline_policies_cache[
                username
            ]

        try:
            paginator = self.iam_client.get_paginator(
                "list_user_policies"
            )

            policy_names: list[str] = []

            for page in paginator.paginate(
                UserName=username,
            ):
                policy_names.extend(
                    page.get(
                        "PolicyNames",
                        [],
                    )
                )

            self._user_inline_policies_cache[
                username
            ] = policy_names

            return policy_names

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM inline policy listing failed for user "
                f"'{username}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing inline policies "
                f"for user '{username}': {exc}"
            ) from exc

    def get_user_policy(
        self,
        username: str,
        policy_name: str,
    ) -> dict[str, Any]:
        """
        Retrieve and normalize an inline IAM user policy.

        AWS returns the policy document URL-encoded. The service
        decodes the document and converts it into a Python dictionary
        so the collector/rule layers do not need to understand the
        AWS response encoding.
        """
        try:
            response = self.iam_client.get_user_policy(
                UserName=username,
                PolicyName=policy_name,
            )

            document = response.get(
                "PolicyDocument",
                {},
            )

            if isinstance(document, str):
                document = json.loads(
                    unquote(document)
                )

            return {
                "policy_name": response.get(
                    "PolicyName",
                    policy_name,
                ),
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
                f"IAM inline policy retrieval failed for user "
                f"'{username}' policy '{policy_name}': "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving inline policy "
                f"'{policy_name}' for user '{username}': {exc}"
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

    def list_groups(self) -> list[dict[str, Any]]:
        """
        Return all IAM groups in the account.

        IAM group listing is paginated, so the service consumes the
        paginator and returns one normalized list for callers.
        """
        try:
            paginator = self.iam_client.get_paginator(
                "list_groups"
            )

            groups: list[dict[str, Any]] = []

            for page in paginator.paginate():
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
                f"IAM group listing failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing IAM groups: "
                f"{exc}"
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

    def list_group_policies(
        self,
        group_name: str,
    ) -> list[str]:
        """
        Return all inline policy names directly attached to an IAM group.

        IAM can paginate inline group policy names, so the service
        consumes the paginator and returns one normalized list.
        """
        try:
            paginator = self.iam_client.get_paginator(
                "list_group_policies"
            )

            policy_names: list[str] = []

            for page in paginator.paginate(
                GroupName=group_name,
            ):
                policy_names.extend(
                    page.get(
                        "PolicyNames",
                        [],
                    )
                )

            return policy_names

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM inline group policy listing failed for "
                f"group '{group_name}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing inline group policies "
                f"for group '{group_name}': {exc}"
            ) from exc

    def get_group_policy(
        self,
        group_name: str,
        policy_name: str,
    ) -> dict[str, Any]:
        """
        Retrieve and normalize an inline IAM group policy.

        AWS returns the policy document URL-encoded. The service
        decodes the document and converts it into a Python dictionary
        so the collector/rule layers do not need to understand the
        AWS response encoding.
        """
        try:
            response = self.iam_client.get_group_policy(
                GroupName=group_name,
                PolicyName=policy_name,
            )

            document = response.get(
                "PolicyDocument",
                {},
            )

            if isinstance(document, str):
                document = json.loads(
                    unquote(document)
                )

            return {
                "policy_name": response.get(
                    "PolicyName",
                    policy_name,
                ),
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
                f"IAM inline group policy retrieval failed for "
                f"group '{group_name}' policy '{policy_name}': "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving inline group policy "
                f"'{policy_name}' for group '{group_name}': {exc}"
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


    def list_roles(self) -> list[dict[str, Any]]:
        try:
            paginator = self.iam_client.get_paginator(
                "list_roles"
            )

            roles: list[dict[str, Any]] = []

            for page in paginator.paginate():
                roles.extend(
                    page.get(
                        "Roles",
                        [],
                    )
                )

            return roles

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM role listing failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while listing IAM roles: "
                f"{exc}"
            ) from exc

    def get_role(
        self,
        role_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.iam_client.get_role(
                RoleName=role_name,
            )

            role = response.get(
                "Role",
                {},
            )

            trust_policy = role.get(
                "AssumeRolePolicyDocument",
                {},
            )

            if isinstance(trust_policy, str):
                trust_policy = json.loads(
                    unquote(trust_policy)
                )

            return {
                "role": role,
                "trust_policy": trust_policy,
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"IAM role retrieval failed for "
                f"'{role_name}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error while retrieving IAM role "
                f"'{role_name}': {exc}"
            ) from exc
