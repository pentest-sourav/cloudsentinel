from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class InspectorService:
    """
    Read-only Amazon Inspector discovery service.

    This service retrieves account-level Inspector scanning
    configuration. Security evaluation is handled separately
    by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.inspector_client = create_aws_client(
            session,
            "inspector2",
        )

    def get_account_status(self) -> dict[str, Any]:
        try:
            response = (
                self.inspector_client.batch_get_account_status()
            )

            accounts = response.get("accounts", [])

            if accounts:
                account = accounts[0]

                state = account.get("state") or {}
                resource_state = (
                    account.get("resourceState") or {}
                )

                return {
                    "account_id": account.get(
                        "accountId"
                    ),
                    "account_status": state.get(
                        "status"
                    ),
                    "account_error_code": state.get(
                        "errorCode"
                    ),
                    "account_error_message": state.get(
                        "errorMessage"
                    ),
                    "ec2_status": (
                        resource_state.get("ec2") or {}
                    ).get("status"),
                    "ec2_error_code": (
                        resource_state.get("ec2") or {}
                    ).get("errorCode"),
                    "ec2_error_message": (
                        resource_state.get("ec2") or {}
                    ).get("errorMessage"),
                    "ecr_status": (
                        resource_state.get("ecr") or {}
                    ).get("status"),
                    "ecr_error_code": (
                        resource_state.get("ecr") or {}
                    ).get("errorCode"),
                    "ecr_error_message": (
                        resource_state.get("ecr") or {}
                    ).get("errorMessage"),
                    "lambda_status": (
                        resource_state.get("lambda") or {}
                    ).get("status"),
                    "lambda_error_code": (
                        resource_state.get("lambda") or {}
                    ).get("errorCode"),
                    "lambda_error_message": (
                        resource_state.get("lambda") or {}
                    ).get("errorMessage"),
                    "lambda_code_status": (
                        resource_state.get("lambdaCode")
                        or {}
                    ).get("status"),
                    "lambda_code_error_code": (
                        resource_state.get("lambdaCode")
                        or {}
                    ).get("errorCode"),
                    "lambda_code_error_message": (
                        resource_state.get("lambdaCode")
                        or {}
                    ).get("errorMessage"),
                }

            failed_accounts = (
                response.get("failedAccounts") or []
            )

            if failed_accounts:
                failed = failed_accounts[0]

                raise RuntimeError(
                    "Amazon Inspector account status "
                    "discovery failed: "
                    f"{failed.get('errorCode', 'UnknownError')}: "
                    f"{failed.get('errorMessage', 'AWS request failed')}"
                )

            raise RuntimeError(
                "Amazon Inspector account status discovery "
                "returned no account data"
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                "Amazon Inspector account status discovery "
                f"failed: {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Amazon Inspector "
                f"account status discovery: {exc}"
            ) from exc
