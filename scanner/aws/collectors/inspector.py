from typing import Any

from scanner.aws.services.inspector import InspectorService


class InspectorDataCollector:
    """
    Normalize Amazon Inspector account status for
    CloudSentinel security rules.
    """

    def __init__(
        self,
        service: InspectorService,
    ):
        self.service = service

        self._account_status_cache: (
            dict[str, Any] | None
        ) = None

    def _get_account_status(
        self,
    ) -> dict[str, Any]:
        if self._account_status_cache is None:
            self._account_status_cache = (
                self.service.get_account_status()
            )

        return self._account_status_cache

    def collect_account_status(
        self,
    ) -> list[dict[str, Any]]:
        account = self._get_account_status()

        account_id = account.get("account_id")

        if not account_id:
            return []

        return [
            {
                "resource_id": account_id,
                "account_id": account_id,
                "account_status": account.get(
                    "account_status"
                ),
                "account_error_code": account.get(
                    "account_error_code"
                ),
                "account_error_message": account.get(
                    "account_error_message"
                ),
                "ec2_status": account.get(
                    "ec2_status"
                ),
                "ec2_error_code": account.get(
                    "ec2_error_code"
                ),
                "ec2_error_message": account.get(
                    "ec2_error_message"
                ),
                "ecr_status": account.get(
                    "ecr_status"
                ),
                "ecr_error_code": account.get(
                    "ecr_error_code"
                ),
                "ecr_error_message": account.get(
                    "ecr_error_message"
                ),
                "lambda_status": account.get(
                    "lambda_status"
                ),
                "lambda_error_code": account.get(
                    "lambda_error_code"
                ),
                "lambda_error_message": account.get(
                    "lambda_error_message"
                ),
                "lambda_code_status": account.get(
                    "lambda_code_status"
                ),
                "lambda_code_error_code": account.get(
                    "lambda_code_error_code"
                ),
                "lambda_code_error_message": account.get(
                    "lambda_code_error_message"
                ),
            }
        ]
