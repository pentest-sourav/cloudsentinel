from datetime import datetime, timezone
from typing import Any

from scanner.aws.services.iam import IAMService


class IAMDataCollector:
    """
    Collect IAM data required by CloudSentinel IAM rules.

    The collector caches the IAM user list so multiple IAM
    data sources can reuse the same AWS API response during
    a single scan.
    """

    def __init__(self, service: IAMService):
        self.service = service
        self._users_cache: list[dict[str, Any]] | None = None

    def _get_users(self) -> list[dict[str, Any]]:
        """
        Return IAM users using a per-scan cache.
        """
        if self._users_cache is None:
            self._users_cache = self.service.list_users()

        return self._users_cache

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

        return collected_access_keys
