from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class SecretsManagerService:
    """
    Read-only AWS Secrets Manager discovery service.

    This service retrieves secret metadata only.
    Secret values are never requested or returned.
    """

    def __init__(self, session):
        self.session = session
        self.client = create_aws_client(
            session,
            "secretsmanager",
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
                f"Secrets Manager {operation} failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during Secrets Manager "
            f"{operation}: {exc}"
        ) from exc

    def list_secrets(self) -> list[dict[str, Any]]:
        try:
            secrets: list[dict[str, Any]] = []
            next_token: str | None = None

            while True:
                request: dict[str, Any] = {
                    "IncludePlannedDeletion": False,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.client.list_secrets(
                    **request,
                )

                entries = response.get(
                    "SecretList",
                    [],
                )

                if isinstance(entries, list):
                    secrets.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                next_token = response.get(
                    "NextToken"
                )

                if (
                    not isinstance(next_token, str)
                    or not next_token
                ):
                    break

            return secrets

        except Exception as exc:
            self._raise_api_error(
                "secret discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_secret(
        self,
        secret_id: str,
    ) -> dict[str, Any]:
        try:
            response = self.client.describe_secret(
                SecretId=secret_id,
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                f"secret lookup for {secret_id}",
                exc,
            )
            raise AssertionError("unreachable")
