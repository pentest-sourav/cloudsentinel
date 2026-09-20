import csv
import io
from datetime import datetime, timezone
from typing import Any

from scanner.aws.services.iam import IAMService


class IAMDataCollector:
    """
    Collect IAM data required by CloudSentinel IAM rules.

    The collector caches IAM users, access-key data, password
    policy data, credential-report data, and attached-user-policy
    data so multiple IAM rules can reuse the same AWS API
    responses during a single scan.
    """

    def __init__(self, service: IAMService):
        self.service = service

        self._users_cache: list[dict[str, Any]] | None = None
        self._access_keys_cache: list[dict[str, Any]] | None = None
        self._password_policy_cache: dict[str, Any] | None = None
        self._credential_report_cache: list[dict[str, Any]] | None = None
        self._attached_user_policies_cache: list[
            dict[str, Any]
        ] | None = None

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

    def collect_root_mfa(self) -> dict[str, Any]:
        return {
            "root_mfa_enabled": self.service.get_root_mfa_status(),
        }

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
                            }
                        )

            self._attached_user_policies_cache = (
                collected_policies
            )

        return self._attached_user_policies_cache
