from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class SecurityHubService:
    """Read-only AWS Security Hub CSPM discovery service."""

    def __init__(self, session):
        self.session = session
        self.securityhub_client = create_aws_client(
            session,
            "securityhub",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
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
                f"Security Hub {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Security Hub "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Security Hub "
            f"{operation}: {exc}"
        ) from exc

    def describe_hub(
        self,
    ) -> dict[str, Any] | None:
        try:
            response = (
                self.securityhub_client.describe_hub()
            )

            if not isinstance(response, dict):
                return {}

            return response

        except ClientError as exc:
            code = (
                exc.response
                .get("Error", {})
                .get("Code")
            )

            if code == "ResourceNotFoundException":
                return None

            self._raise_api_error(
                "hub discovery",
                exc,
            )
            raise AssertionError("unreachable")

        except (BotoCoreError, Exception) as exc:
            self._raise_api_error(
                "hub discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_enabled_standards(
        self,
    ) -> list[dict[str, Any]]:
        standards: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 100,
                    "Providers": ["AWS"],
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    self.securityhub_client
                    .get_enabled_standards(
                        **request
                    )
                )

                page = response.get(
                    "StandardsSubscriptions",
                    [],
                )

                if isinstance(page, list):
                    standards.extend(
                        item
                        for item in page
                        if isinstance(item, dict)
                    )

                next_token = response.get("NextToken")

                if not next_token:
                    break

            return standards

        except Exception as exc:
            self._raise_api_error(
                "enabled standards discovery",
                exc,
            )
            raise AssertionError("unreachable")
