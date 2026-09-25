from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class MacieService:
    """
    Read-only Amazon Macie discovery service.

    This service retrieves Macie account and automated
    sensitive data discovery configuration only.
    It never enables, disables, or mutates Macie.
    """

    def __init__(self, session):
        self.session = session
        self.macie_client = create_aws_client(
            session,
            "macie2",
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
                f"Macie {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during Macie "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during Macie "
            f"{operation}: {exc}"
        ) from exc

    def get_macie_session(self) -> dict[str, Any]:
        try:
            response = (
                self.macie_client.get_macie_session()
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                "session discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_administrator_account(
        self,
    ) -> dict[str, Any] | None:
        try:
            response = (
                self.macie_client.get_administrator_account()
            )

            if not isinstance(response, dict):
                return None

            return response

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get(
                "Code",
                "UnknownError",
            )

            if code == "ResourceNotFoundException":
                return None

            self._raise_api_error(
                "administrator discovery",
                exc,
            )
            raise AssertionError("unreachable")

        except Exception as exc:
            self._raise_api_error(
                "administrator discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_automated_discovery_configuration(
        self,
    ) -> dict[str, Any]:
        try:
            response = (
                self.macie_client
                .get_automated_discovery_configuration()
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                "automated discovery configuration",
                exc,
            )
            raise AssertionError("unreachable")
