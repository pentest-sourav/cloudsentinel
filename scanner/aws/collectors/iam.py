import csv
import io
from datetime import datetime, timezone
from typing import Any

from scanner.aws.services.iam import IAMService


class IAMDataCollector:
    """
    Collect IAM data required by CloudSentinel IAM rules.

    The collector caches IAM users, access-key data, password
    policy data, credential-report data, attached-user-policy
    data, user-group membership data, attached-group-policy
    data, inline-user-policy data, inline-group-policy data,
    and access-key last-used data so multiple IAM rules can reuse
    the same AWS API responses during a single scan.
    """

    def __init__(self, service: IAMService):
        self.service = service

        self._users_cache: list[dict[str, Any]] | None = None
        self._access_keys_cache: list[dict[str, Any]] | None = None
        self._access_key_last_used_cache: dict[
            str,
            datetime | None,
        ] = {}
        self._password_policy_cache: dict[str, Any] | None = None
        self._credential_report_cache: list[dict[str, Any]] | None = None

        self._attached_user_policies_cache: list[
            dict[str, Any]
        ] | None = None

        self._broad_user_inline_policies_cache: list[
            dict[str, Any]
        ] | None = None

        self._groups_for_user_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._attached_group_policies_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._broad_group_policies_cache: list[
            dict[str, Any]
        ] | None = None

        self._groups_cache: list[dict[str, Any]] | None = None

        self._group_inline_policies_cache: list[
            dict[str, Any]
        ] | None = None

        self._broad_action_restricted_resources_cache: list[
            dict[str, Any]
        ] | None = None

        self._roles_cache: list[dict[str, Any]] | None = None

        self._role_trust_policy_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def _get_users(self) -> list[dict[str, Any]]:
        """
        Return IAM users using a per-scan cache.
        """
        if self._users_cache is None:
            self._users_cache = self.service.list_users()

        return self._users_cache

    def _get_access_keys(self) -> list[dict[str, Any]]:
        """
        Return normalized IAM access keys using a per-scan cache.
        """
        if self._access_keys_cache is None:
            users = self._get_users()

            current_time = datetime.now(timezone.utc)

            collected_access_keys: list[dict[str, Any]] = []

            for user in users:
                username = user["UserName"]

                access_keys = self.service.list_access_keys(
                    username
                )

                for access_key in access_keys:
                    collected_access_keys.append(
                        {
                            "username": username,
                            "access_key_id": access_key[
                                "AccessKeyId"
                            ],
                            "status": access_key["Status"],
                            "created_at": access_key["CreateDate"],
                            "current_time": current_time,
                        }
                    )

            self._access_keys_cache = collected_access_keys

        return self._access_keys_cache

    def _get_groups_for_user(
        self,
        username: str,
    ) -> list[dict[str, Any]]:
        """
        Return IAM groups for a user using a per-scan cache.
        """
        if username not in self._groups_for_user_cache:
            self._groups_for_user_cache[username] = (
                self.service.list_groups_for_user(
                    username
                )
            )

        return self._groups_for_user_cache[username]

    def _get_groups(self) -> list[dict[str, Any]]:
        """
        Return all IAM groups using a per-scan cache.

        This cache is intentionally separate from the user-to-group
        membership cache because IAM-015 evaluates inline policies
        attached to every group, including groups that are not
        currently associated with a discovered IAM user.
        """
        if self._groups_cache is None:
            self._groups_cache = self.service.list_groups()

        return self._groups_cache

    def _get_attached_group_policies(
        self,
        group_name: str,
    ) -> list[dict[str, Any]]:
        """
        Return managed policies directly attached to an IAM group.

        Group policy data is cached by group name so the same group is
        never queried repeatedly during a single scan.
        """
        if group_name not in self._attached_group_policies_cache:
            self._attached_group_policies_cache[group_name] = (
                self.service.list_attached_group_policies(
                    group_name
                )
            )

        return self._attached_group_policies_cache[group_name]

    def _collect_group_policy_statements(
        self,
        username: str,
        group_name: str,
        attached_policies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Collect normalized statements from managed policies attached
        directly to an IAM group.

        Only the default policy version is evaluated. Policy
        interpretation remains the responsibility of the rule layer.
        """
        collected_policies: list[dict[str, Any]] = []

        for attached_policy in attached_policies:
            policy_arn = attached_policy.get(
                "PolicyArn"
            )

            policy_name = attached_policy.get(
                "PolicyName"
            )

            if not policy_arn:
                continue

            policy = self.service.get_policy(
                policy_arn
            )

            default_version_id = policy.get(
                "DefaultVersionId"
            )

            if not default_version_id:
                continue

            version = self.service.get_policy_version(
                policy_arn,
                default_version_id,
            )

            document = version.get(
                "document",
                {},
            )

            if not isinstance(document, dict):
                continue

            statements = document.get(
                "Statement",
                [],
            )

            if isinstance(statements, dict):
                statements = [statements]

            if not isinstance(statements, list):
                continue

            for statement in statements:
                if not isinstance(statement, dict):
                    continue

                collected_policies.append(
                    {
                        "username": username,
                        "group_name": group_name,
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "policy_version_id": (
                            default_version_id
                        ),
                        "effect": statement.get(
                            "Effect"
                        ),
                        "action": statement.get(
                            "Action"
                        ),
                        "resource": statement.get(
                            "Resource"
                        ),
                        "condition": statement.get(
                            "Condition"
                        ),
                        "not_action": statement.get(
                            "NotAction"
                        ),
                        "not_resource": statement.get(
                            "NotResource"
                        ),
                    }
                )

        return collected_policies

    def _collect_user_inline_policy_statements(
        self,
        username: str,
        policy_name: str,
    ) -> list[dict[str, Any]]:
        """
        Collect normalized statements from an inline IAM user policy.

        Inline policies are evaluated directly from the policy document
        returned by IAM. Policy interpretation remains the
        responsibility of the rule layer.

        Each normalized statement includes its zero-based statement
        index so downstream findings can identify the exact statement
        that triggered a rule.
        """
        policy_response = self.service.get_user_policy(
            username,
            policy_name,
        )

        document = policy_response.get(
            "document",
            {},
        )

        if not isinstance(document, dict):
            return []

        statements = document.get(
            "Statement",
            [],
        )

        if isinstance(statements, dict):
            statements = [statements]

        if not isinstance(statements, list):
            return []

        collected_statements: list[dict[str, Any]] = []

        for statement_index, statement in enumerate(statements):
            if not isinstance(statement, dict):
                continue

            collected_statements.append(
                {
                    "username": username,
                    "policy_name": policy_name,
                    "statement_index": statement_index,
                    "effect": statement.get(
                        "Effect"
                    ),
                    "action": statement.get(
                        "Action"
                    ),
                    "resource": statement.get(
                        "Resource"
                    ),
                    "condition": statement.get(
                        "Condition"
                    ),
                    "not_action": statement.get(
                        "NotAction"
                    ),
                    "not_resource": statement.get(
                        "NotResource"
                    ),
                }
            )

        return collected_statements

    def _collect_group_inline_policy_statements(
        self,
        group_name: str,
        policy_name: str,
    ) -> list[dict[str, Any]]:
        """
        Collect normalized statements from an inline IAM group policy.

        Each normalized statement includes its zero-based statement
        index so downstream rules can identify the exact statement
        that triggered a rule.

        Policy interpretation remains the responsibility of the rule
        layer.
        """
        policy_response = self.service.get_group_policy(
            group_name,
            policy_name,
        )

        document = policy_response.get(
            "document",
            {},
        )

        if not isinstance(document, dict):
            return []

        statements = document.get(
            "Statement",
            [],
        )

        if isinstance(statements, dict):
            statements = [statements]

        if not isinstance(statements, list):
            return []

        collected_statements: list[dict[str, Any]] = []

        for statement_index, statement in enumerate(statements):
            if not isinstance(statement, dict):
                continue

            collected_statements.append(
                {
                    "group_name": group_name,
                    "policy_name": policy_name,
                    "statement_index": statement_index,
                    "effect": statement.get(
                        "Effect"
                    ),
                    "action": statement.get(
                        "Action"
                    ),
                    "resource": statement.get(
                        "Resource"
                    ),
                    "condition": statement.get(
                        "Condition"
                    ),
                    "not_action": statement.get(
                        "NotAction"
                    ),
                    "not_resource": statement.get(
                        "NotResource"
                    ),
                }
            )

        return collected_statements

    def collect_root_mfa(self) -> dict[str, Any]:
        return {
            "root_mfa_enabled": self.service.get_root_mfa_status(),
        }

    def collect_root_access_key(self) -> dict[str, Any]:
        """
        Collect root-user access-key state for IAM-021.

        The IAM service reuses its cached account summary, so this
        does not introduce an additional GetAccountSummary call
        when root MFA is also evaluated during the same scan.
        """
        return {
            "access_keys_present": (
                self.service.get_root_access_keys_present()
            ),
        }

    def collect_user_attached_policies(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect directly attached managed and inline policies
        for every IAM user.

        The IAM service caches policy-list responses per user,
        allowing IAM-012, IAM-014, IAM-016, and IAM-022 to reuse
        the same underlying AWS API results.

        This collector only gathers attachment state. It does not
        evaluate whether the attached policies are overly broad.
        """
        users = self._get_users()

        results: list[dict[str, Any]] = []

        for user in users:
            username = user.get(
                "UserName"
            )

            if not username:
                continue

            managed_policies = (
                self.service.list_attached_user_policies(
                    username
                )
            )

            inline_policy_names = (
                self.service.list_user_policies(
                    username
                )
            )

            managed_policy_names = [
                policy.get(
                    "PolicyName",
                    "",
                )
                for policy in managed_policies
                if policy.get(
                    "PolicyName"
                )
            ]

            results.append(
                {
                    "username": username,
                    "managed_policy_count": len(
                        managed_policy_names
                    ),
                    "managed_policy_names": (
                        managed_policy_names
                    ),
                    "inline_policy_count": len(
                        inline_policy_names
                    ),
                    "inline_policy_names": (
                        inline_policy_names
                    ),
                }
            )

        return results

    def collect_iam_users(self) -> list[dict[str, Any]]:
        users = self._get_users()

        collected_users: list[dict[str, Any]] = []

        for user in users:
            username = user["UserName"]

            mfa_devices = self.service.list_mfa_devices(
                username
            )

            collected_users.append(
                {
                    "username": username,
                    "mfa_devices": mfa_devices,
                }
            )

        return collected_users

    def collect_iam_access_keys(self) -> list[dict[str, Any]]:
        return self._get_access_keys()

    def collect_access_key_last_used(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect last-used metadata for active IAM access keys.

        Existing access-key metadata is reused from the per-scan cache.
        The AWS GetAccessKeyLastUsed API is called only for active
        access keys, and the result is cached by access-key ID.
        """
        collected: list[dict[str, Any]] = []

        for access_key in self._get_access_keys():
            if access_key["status"] != "Active":
                continue

            access_key_id = access_key["access_key_id"]

            if access_key_id not in self._access_key_last_used_cache:
                self._access_key_last_used_cache[access_key_id] = (
                    self.service.get_access_key_last_used(
                        access_key_id
                    )
                )

            collected.append(
                {
                    "username": access_key["username"],
                    "access_key_id": access_key_id,
                    "status": access_key["status"],
                    "last_used_at": (
                        self._access_key_last_used_cache[
                            access_key_id
                        ]
                    ),
                }
            )

        return collected

    def collect_password_policy(self) -> dict[str, Any]:
        """
        Return normalized IAM password policy using a per-scan cache.
        """
        if self._password_policy_cache is None:
            self._password_policy_cache = (
                self.service.get_account_password_policy()
            )

        policy = self._password_policy_cache

        return {
            "minimum_password_length": policy.get(
                "MinimumPasswordLength",
                0,
            ),
            "require_symbols": policy.get(
                "RequireSymbols",
                False,
            ),
            "require_numbers": policy.get(
                "RequireNumbers",
                False,
            ),
            "require_uppercase": policy.get(
                "RequireUppercaseCharacters",
                False,
            ),
            "require_lowercase": policy.get(
                "RequireLowercaseCharacters",
                False,
            ),
            "password_reuse_prevention": policy.get(
                "PasswordReusePrevention",
                0,
            ),
        }

    def collect_credential_report(self) -> list[dict[str, Any]]:
        """
        Return normalized IAM credential report data using a
        per-scan cache.

        Credential-report timestamps are converted to timezone-aware
        datetime objects so IAM rules can safely perform age
        calculations.
        """
        if self._credential_report_cache is None:
            report = self.service.get_credential_report()

            content = report.get(
                "Content",
                b"",
            )

            if isinstance(content, bytes):
                content = content.decode("utf-8")

            reader = csv.DictReader(
                io.StringIO(content)
            )

            current_time = datetime.now(timezone.utc)

            collected_users: list[dict[str, Any]] = []

            for row in reader:
                password_last_used = row.get(
                    "password_last_used"
                )

                if password_last_used in (
                    None,
                    "",
                    "N/A",
                    "no_information",
                ):
                    password_last_used = None
                else:
                    password_last_used = (
                        datetime.fromisoformat(
                            password_last_used.replace(
                                "Z",
                                "+00:00",
                            )
                        )
                    )

                    if password_last_used.tzinfo is None:
                        password_last_used = (
                            password_last_used.replace(
                                tzinfo=timezone.utc
                            )
                        )

                collected_users.append(
                    {
                        "username": row.get(
                            "user",
                            "",
                        ),
                        "password_enabled": (
                            row.get(
                                "password_enabled",
                                "false",
                            ).lower()
                            == "true"
                        ),
                        "password_last_used": password_last_used,
                        "current_time": current_time,
                    }
                )

            self._credential_report_cache = collected_users

        return self._credential_report_cache

    def collect_stale_iam_users(
        self,
        threshold_days: int = 90,
    ) -> list[dict[str, Any]]:
        """
        Collect IAM users whose latest known authentication activity
        is older than the stale-user threshold.

        IAM-023 evaluates the latest known activity from:
        - console password usage
        - active access-key usage

        Users with no known historical authentication activity are
        intentionally excluded here because IAM-019 and IAM-020
        already cover never-used credentials and users with no active
        authentication credentials.

        Existing credential-report and access-key caches are reused,
        and active access-key last-used information is obtained through
        the existing per-access-key cache.
        """
        credential_report = self.collect_credential_report()
        access_key_last_used = self.collect_access_key_last_used()

        access_key_activity_by_user: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        for access_key in access_key_last_used:
            last_used_at = access_key.get(
                "last_used_at"
            )

            if last_used_at is None:
                continue

            username = access_key.get(
                "username"
            )

            if not username:
                continue

            access_key_activity_by_user.setdefault(
                username,
                [],
            ).append(
                {
                    "last_activity_at": last_used_at,
                    "access_key_id": access_key.get(
                        "access_key_id"
                    ),
                }
            )

        results: list[dict[str, Any]] = []

        for user in credential_report:
            username = user.get(
                "username"
            )

            if not username:
                continue

            current_time = user.get(
                "current_time"
            )

            if not isinstance(current_time, datetime):
                continue

            activity_candidates: list[
                tuple[datetime, str, str | None]
            ] = []

            password_last_used = user.get(
                "password_last_used"
            )

            if isinstance(password_last_used, datetime):
                activity_candidates.append(
                    (
                        password_last_used,
                        "console_password",
                        None,
                    )
                )

            for access_key_activity in (
                access_key_activity_by_user.get(
                    username,
                    [],
                )
            ):
                last_used_at = access_key_activity.get(
                    "last_activity_at"
                )

                if not isinstance(last_used_at, datetime):
                    continue

                activity_candidates.append(
                    (
                        last_used_at,
                        "access_key",
                        access_key_activity.get(
                            "access_key_id"
                        ),
                    )
                )

            # No known activity:
            # intentionally leave this user for IAM-019/IAM-020.
            if not activity_candidates:
                continue

            last_activity_at, last_activity_type, access_key_id = (
                max(
                    activity_candidates,
                    key=lambda item: item[0],
                )
            )

            if last_activity_at.tzinfo is None:
                last_activity_at = last_activity_at.replace(
                    tzinfo=timezone.utc
                )

            if current_time.tzinfo is None:
                current_time = current_time.replace(
                    tzinfo=timezone.utc
                )

            age_days = (
                current_time - last_activity_at
            ).days

            if age_days <= threshold_days:
                continue

            results.append(
                {
                    "username": username,
                    "last_activity_at": last_activity_at,
                    "last_activity_type": last_activity_type,
                    "last_activity_access_key_id": (
                        access_key_id
                    ),
                    "current_time": current_time,
                }
            )

        return results

    def collect_no_active_authentication_credentials(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect authentication-credential state for every IAM user.

        IAM-020 reports users that have neither an enabled console
        password nor an active programmatic access key.

        Existing credential-report and access-key caches are reused,
        so this method does not introduce additional AWS API calls.
        """
        credential_report = self.collect_credential_report()
        access_keys = self.collect_iam_access_keys()

        active_keys_by_user: dict[str, list[str]] = {}

        for access_key in access_keys:
            if access_key["status"] != "Active":
                continue

            username = access_key["username"]

            active_keys_by_user.setdefault(
                username,
                [],
            ).append(
                access_key["access_key_id"]
            )

        results: list[dict[str, Any]] = []

        for user in credential_report:
            username = user["username"]

            active_access_key_ids = active_keys_by_user.get(
                username,
                [],
            )

            results.append(
                {
                    "username": username,
                    "password_enabled": user[
                        "password_enabled"
                    ],
                    "active_access_key_count": len(
                        active_access_key_ids
                    ),
                    "active_access_key_ids": active_access_key_ids,
                }
            )

        return results

    def collect_administrative_group_policies(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect direct AdministratorAccess attachments for every
        IAM group.

        This intentionally evaluates all groups, including groups
        without current members, so IAM-026 cannot miss an
        administrative group that is temporarily unused.

        Existing group and attached-policy caches are reused to
        avoid duplicate AWS API calls during the same scan.
        """
        groups = self._get_groups()

        results: list[dict[str, Any]] = []

        for group in groups:
            group_name = group.get("GroupName")

            if not group_name:
                continue

            attached_policies = (
                self._get_attached_group_policies(
                    group_name
                )
            )

            for attached_policy in attached_policies:
                policy_name = attached_policy.get(
                    "PolicyName"
                )
                policy_arn = attached_policy.get(
                    "PolicyArn"
                )

                if (
                    policy_name
                    != "AdministratorAccess"
                ):
                    continue

                if (
                    policy_arn
                    != "arn:aws:iam::aws:policy/"
                    "AdministratorAccess"
                ):
                    continue

                results.append(
                    {
                        "group_name": group_name,
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                    }
                )

        return results

    def collect_broad_user_policies(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect normalized directly attached managed IAM policies
        for every IAM user.

        Only the default policy version is evaluated. The collector
        intentionally preserves the policy statement structure so
        rules remain responsible for deciding whether a permission
        represents a security finding.
        """
        if self._attached_user_policies_cache is None:
            users = self._get_users()

            collected_policies: list[dict[str, Any]] = []

            for user in users:
                username = user["UserName"]

                attached_policies = (
                    self.service.list_attached_user_policies(
                        username
                    )
                )

                for attached_policy in attached_policies:
                    policy_arn = attached_policy.get(
                        "PolicyArn"
                    )

                    policy_name = attached_policy.get(
                        "PolicyName"
                    )

                    if not policy_arn:
                        continue

                    policy = self.service.get_policy(
                        policy_arn
                    )

                    default_version_id = policy.get(
                        "DefaultVersionId"
                    )

                    if not default_version_id:
                        continue

                    version = self.service.get_policy_version(
                        policy_arn,
                        default_version_id,
                    )

                    document = version.get(
                        "document",
                        {},
                    )

                    statements = document.get(
                        "Statement",
                        [],
                    )

                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:
                        if not isinstance(statement, dict):
                            continue

                        collected_policies.append(
                            {
                                "username": username,
                                "policy_name": policy_name,
                                "policy_arn": policy_arn,
                                "policy_version_id": (
                                    default_version_id
                                ),
                                "effect": statement.get(
                                    "Effect"
                                ),
                                "action": statement.get(
                                    "Action"
                                ),
                                "resource": statement.get(
                                    "Resource"
                                ),
                                "condition": statement.get(
                                    "Condition"
                                ),
                                "not_action": statement.get(
                                    "NotAction"
                                ),
                                "not_resource": statement.get(
                                    "NotResource"
                                ),
                            }
                        )

            self._attached_user_policies_cache = (
                collected_policies
            )

        return self._attached_user_policies_cache

    def collect_broad_user_inline_policies(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect normalized statements from inline IAM policies
        directly attached to IAM users.

        Each inline policy is retrieved from IAM and normalized into
        one record per policy statement. The zero-based statement
        index is preserved so downstream rules can identify the exact
        statement that produced a finding.

        Policy interpretation remains the responsibility of the rule
        layer.
        """
        if self._broad_user_inline_policies_cache is None:
            users = self._get_users()

            collected_policies: list[dict[str, Any]] = []

            for user in users:
                username = user["UserName"]

                policy_names = self.service.list_user_policies(
                    username
                )

                for policy_name in policy_names:
                    collected_policies.extend(
                        self._collect_user_inline_policy_statements(
                            username=username,
                            policy_name=policy_name,
                        )
                    )

            self._broad_user_inline_policies_cache = (
                collected_policies
            )

        return self._broad_user_inline_policies_cache

    def collect_broad_group_policies(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect normalized managed policies directly attached to
        IAM groups that are assigned to IAM users.

        The collector preserves the user-to-group-to-policy
        relationship so downstream rules can identify exactly
        which group introduces the broad permission.

        Only the default policy version is evaluated. Policy
        interpretation remains the responsibility of the rule layer.
        """
        if self._broad_group_policies_cache is None:
            users = self._get_users()

            collected_policies: list[dict[str, Any]] = []

            for user in users:
                username = user["UserName"]

                groups = self._get_groups_for_user(
                    username
                )

                for group in groups:
                    group_name = group.get(
                        "GroupName"
                    )

                    if not group_name:
                        continue

                    attached_policies = (
                        self._get_attached_group_policies(
                            group_name
                        )
                    )

                    collected_policies.extend(
                        self._collect_group_policy_statements(
                            username=username,
                            group_name=group_name,
                            attached_policies=attached_policies,
                        )
                    )

            self._broad_group_policies_cache = (
                collected_policies
            )

        return self._broad_group_policies_cache

    def collect_broad_group_inline_policies(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect normalized statements from inline IAM policies
        directly attached to every IAM group.

        All groups are evaluated independently of current user
        membership so security findings are not missed for groups
        that currently have no discovered members.

        Each normalized statement includes its zero-based statement
        index so downstream rules can identify the exact statement
        that produced a finding.

        Policy interpretation remains the responsibility of the rule
        layer.
        """
        if self._group_inline_policies_cache is None:
            groups = self._get_groups()

            collected_policies: list[dict[str, Any]] = []

            for group in groups:
                group_name = group.get(
                    "GroupName"
                )

                if not group_name:
                    continue

                policy_names = self.service.list_group_policies(
                    group_name
                )

                for policy_name in policy_names:
                    collected_policies.extend(
                        self._collect_group_inline_policy_statements(
                            group_name=group_name,
                            policy_name=policy_name,
                        )
                    )

            self._group_inline_policies_cache = (
                collected_policies
            )

        return self._group_inline_policies_cache

    def _normalize_broad_action_restricted_resource(
        self,
        *,
        permission_source: str,
        principal_type: str,
        principal_id: str,
        username: str | None,
        group_name: str | None,
        policy_name: str,
        policy_arn: str | None,
        policy_version_id: str | None,
        statement_index: int | None,
        effect: Any,
        action: Any,
        resource: Any,
        condition: Any,
        not_action: Any,
        not_resource: Any,
    ) -> dict[str, Any]:
        """
        Normalize a permission statement into the common IAM-016
        schema.

        The normalized record intentionally contains only collection
        data. Detection logic remains in the IAM-016 rule layer.
        """
        return {
            "permission_source": permission_source,
            "resource_id": principal_id,
            "principal_type": principal_type,
            "principal_id": principal_id,
            "username": username,
            "group_name": group_name,
            "policy_name": policy_name,
            "policy_arn": policy_arn,
            "policy_version_id": policy_version_id,
            "statement_index": statement_index,
            "effect": effect,
            "action": action,
            "resource": resource,
            "condition": condition,
            "not_action": not_action,
            "not_resource": not_resource,
        }

    def collect_broad_action_restricted_resources(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect IAM permission statements from all four permission
        sources required by CS-AWS-IAM-016.

        Sources:

        1. Directly attached managed policies on IAM users.
        2. Managed policies attached to IAM groups assigned to users.
        3. Inline policies directly attached to IAM users.
        4. Inline policies directly attached to IAM groups.

        Every source is normalized into one common schema so the
        IAM-016 rule can evaluate all permission sources through one
        RuleDefinition.

        Existing collector methods and their caches are reused to
        avoid unnecessary duplicate AWS API calls during a scan.

        The collector does not decide whether a permission is broad.
        It only gathers and normalizes the permission statements.
        """
        if self._broad_action_restricted_resources_cache is None:
            collected_resources: list[dict[str, Any]] = []

            user_managed_policies = (
                self.collect_broad_user_policies()
            )

            for statement in user_managed_policies:
                username = statement.get(
                    "username"
                )

                if not username:
                    continue

                collected_resources.append(
                    self._normalize_broad_action_restricted_resource(
                        permission_source="user_managed_policy",
                        principal_type="user",
                        principal_id=username,
                        username=username,
                        group_name=None,
                        policy_name=statement.get(
                            "policy_name",
                            "",
                        ),
                        policy_arn=statement.get(
                            "policy_arn"
                        ),
                        policy_version_id=statement.get(
                            "policy_version_id"
                        ),
                        statement_index=None,
                        effect=statement.get(
                            "effect"
                        ),
                        action=statement.get(
                            "action"
                        ),
                        resource=statement.get(
                            "resource"
                        ),
                        condition=statement.get(
                            "condition"
                        ),
                        not_action=statement.get(
                            "not_action"
                        ),
                        not_resource=statement.get(
                            "not_resource"
                        ),
                    )
                )

            group_managed_policies = (
                self.collect_broad_group_policies()
            )

            for statement in group_managed_policies:
                group_name = statement.get(
                    "group_name"
                )

                if not group_name:
                    continue

                collected_resources.append(
                    self._normalize_broad_action_restricted_resource(
                        permission_source="group_managed_policy",
                        principal_type="group",
                        principal_id=group_name,
                        username=statement.get(
                            "username"
                        ),
                        group_name=group_name,
                        policy_name=statement.get(
                            "policy_name",
                            "",
                        ),
                        policy_arn=statement.get(
                            "policy_arn"
                        ),
                        policy_version_id=statement.get(
                            "policy_version_id"
                        ),
                        statement_index=None,
                        effect=statement.get(
                            "effect"
                        ),
                        action=statement.get(
                            "action"
                        ),
                        resource=statement.get(
                            "resource"
                        ),
                        condition=statement.get(
                            "condition"
                        ),
                        not_action=statement.get(
                            "not_action"
                        ),
                        not_resource=statement.get(
                            "not_resource"
                        ),
                    )
                )

            user_inline_policies = (
                self.collect_broad_user_inline_policies()
            )

            for statement in user_inline_policies:
                username = statement.get(
                    "username"
                )

                if not username:
                    continue

                collected_resources.append(
                    self._normalize_broad_action_restricted_resource(
                        permission_source="user_inline_policy",
                        principal_type="user",
                        principal_id=username,
                        username=username,
                        group_name=None,
                        policy_name=statement.get(
                            "policy_name",
                            "",
                        ),
                        policy_arn=None,
                        policy_version_id=None,
                        statement_index=statement.get(
                            "statement_index"
                        ),
                        effect=statement.get(
                            "effect"
                        ),
                        action=statement.get(
                            "action"
                        ),
                        resource=statement.get(
                            "resource"
                        ),
                        condition=statement.get(
                            "condition"
                        ),
                        not_action=statement.get(
                            "not_action"
                        ),
                        not_resource=statement.get(
                            "not_resource"
                        ),
                    )
                )

            group_inline_policies = (
                self.collect_broad_group_inline_policies()
            )

            for statement in group_inline_policies:
                group_name = statement.get(
                    "group_name"
                )

                if not group_name:
                    continue

                collected_resources.append(
                    self._normalize_broad_action_restricted_resource(
                        permission_source="group_inline_policy",
                        principal_type="group",
                        principal_id=group_name,
                        username=None,
                        group_name=group_name,
                        policy_name=statement.get(
                            "policy_name",
                            "",
                        ),
                        policy_arn=None,
                        policy_version_id=None,
                        statement_index=statement.get(
                            "statement_index"
                        ),
                        effect=statement.get(
                            "effect"
                        ),
                        action=statement.get(
                            "action"
                        ),
                        resource=statement.get(
                            "resource"
                        ),
                        condition=statement.get(
                            "condition"
                        ),
                        not_action=statement.get(
                            "not_action"
                        ),
                        not_resource=statement.get(
                            "not_resource"
                        ),
                    )
                )

            self._broad_action_restricted_resources_cache = (
                collected_resources
            )

        return self._broad_action_restricted_resources_cache


    def collect_privileged_users_without_boundary(
        self,
    ) -> list[dict[str, Any]]:
        """
        Reuse normalized IAM policy statements and IAM user metadata
        to identify privileged users without a permissions boundary.

        No additional AWS policy API calls are introduced here.
        """
        users = self._get_users()

        boundaries = {
            user.get("UserName"): (
                user.get("PermissionsBoundary", {})
                .get("PermissionsBoundaryArn")
                if isinstance(
                    user.get("PermissionsBoundary"),
                    dict,
                )
                else None
            )
            for user in users
            if user.get("UserName")
        }

        policy_statements = (
            self.collect_broad_action_restricted_resources()
        )

        results: list[dict[str, Any]] = []

        for statement in policy_statements:
            username = statement.get("username")

            if not username:
                continue

            if boundaries.get(username):
                continue

            results.append(
                {
                    "username": username,
                    "permissions_boundary": None,
                    "policy_name": statement.get(
                        "policy_name",
                        "",
                    ),
                    "policy_arn": statement.get(
                        "policy_arn"
                    ),
                    "action": statement.get(
                        "action"
                    ),
                    "resource": statement.get(
                        "resource"
                    ),
                    "permission_source": statement.get(
                        "permission_source",
                        "",
                    ),
                    "condition": statement.get(
                        "condition"
                    ),
                }
            )

        return results


    def _get_roles(self) -> list[dict[str, Any]]:
        if self._roles_cache is None:
            self._roles_cache = self.service.list_roles()

        return self._roles_cache


    def _get_role_trust_policy(
        self,
        role_name: str,
    ) -> dict[str, Any]:
        if role_name not in self._role_trust_policy_cache:
            self._role_trust_policy_cache[role_name] = (
                self.service.get_role(
                    role_name
                )
            )

        return self._role_trust_policy_cache[role_name]


    def collect_wildcard_role_trust_principals(
        self,
    ) -> list[dict[str, Any]]:
        roles = self._get_roles()

        results: list[dict[str, Any]] = []

        for role in roles:
            role_name = role.get("RoleName")
            role_arn = role.get("Arn")

            if not role_name or not role_arn:
                continue

            role_data = self._get_role_trust_policy(
                role_name
            )

            document = role_data.get(
                "trust_policy",
                {},
            )

            if not isinstance(document, dict):
                continue

            statements = document.get(
                "Statement",
                [],
            )

            if isinstance(statements, dict):
                statements = [statements]

            if not isinstance(statements, list):
                continue

            for statement_index, statement in enumerate(
                statements
            ):
                if not isinstance(statement, dict):
                    continue

                results.append(
                    {
                        "role_name": role_name,
                        "role_arn": role_arn,
                        "statement_index": statement_index,
                        "effect": statement.get(
                            "Effect"
                        ),
                        "principal": statement.get(
                            "Principal"
                        ),
                        "action": statement.get(
                            "Action"
                        ),
                        "condition": statement.get(
                            "Condition"
                        ),
                    }
                )

        return results


    def collect_cross_account_role_trusts(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect IAM role trust-policy statements for IAM-035.

        Reuses the same role and trust-policy caches used by IAM-033,
        so this collector does not introduce additional AWS API calls
        for roles already inspected during the scan.
        """
        results: list[dict[str, Any]] = []

        for role in self._get_roles():
            role_name = role.get("RoleName")
            role_arn = role.get("Arn")

            if not role_name or not role_arn:
                continue

            role_data = self._get_role_trust_policy(
                role_name
            )

            document = role_data.get(
                "trust_policy",
                {},
            )

            if not isinstance(document, dict):
                continue

            statements = document.get(
                "Statement",
                [],
            )

            if isinstance(statements, dict):
                statements = [statements]

            if not isinstance(statements, list):
                continue

            for statement_index, statement in enumerate(
                statements
            ):
                if not isinstance(statement, dict):
                    continue

                results.append(
                    {
                        "role_name": role_name,
                        "role_arn": role_arn,
                        "statement_index": statement_index,
                        "effect": statement.get(
                            "Effect"
                        ),
                        "principal": statement.get(
                            "Principal"
                        ),
                        "action": statement.get(
                            "Action"
                        ),
                        "condition": statement.get(
                            "Condition"
                        ),
                    }
                )

        return results
