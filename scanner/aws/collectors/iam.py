from datetime import datetime, timezone
from typing import Any

from scanner.aws.services.iam import IAMService


class IAMDataCollector:
    """
    Collect IAM data required by CloudSentinel IAM rules.

    The collector caches IAM users, access-key data, and password
    policy data so multiple IAM rules can reuse the same AWS API
    responses during a single scan.
    """

    def __init__(self, service: IAMService):
        self.service = service

        self._users_cache: list[dict[str, Any]] | None = None
        self._access_keys_cache: list[dict[str, Any]] | None = None
        self._password_policy_cache: dict[str, Any] | None = None

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
                            "access_key_id": access_key["AccessKeyId"],
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
        }
