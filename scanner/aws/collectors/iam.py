from typing import Any

from scanner.aws.services.iam import IAMService


class IAMDataCollector:
    """
    Collect IAM data required by CloudSentinel IAM rules.

    This layer talks to IAMService and prepares normalized
    data for the rule engine.
    """

    def __init__(self, service: IAMService):
        self.service = service

    def collect_root_mfa(self) -> dict[str, Any]:
        return {
            "root_mfa_enabled": self.service.get_root_mfa_status(),
        }

    def collect_iam_users(self) -> list[dict[str, Any]]:
        users = self.service.list_users()

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
