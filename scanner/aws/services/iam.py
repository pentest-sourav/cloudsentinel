from typing import Any

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
