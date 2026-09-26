from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class FSxService:
    """
    Read-only Amazon FSx discovery service.

    Retrieves file systems required by CloudSentinel
    Amazon FSx security posture rules.
    """

    def __init__(self, session):
        self.fsx_client = create_aws_client(
            session,
            "fsx",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS FSx {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during FSx "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during FSx "
            f"{operation}: {exc}"
        ) from exc

    def list_file_systems(self) -> list[dict[str, Any]]:
        file_systems: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.fsx_client.describe_file_systems(
                    **request,
                )

                entries = response.get(
                    "FileSystems",
                    [],
                )

                if isinstance(entries, list):
                    file_systems.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                token = response.get("NextToken")

                if (
                    not isinstance(token, str)
                    or not token
                ):
                    break

                next_token = token

            return file_systems

        except Exception as exc:
            self._raise_api_error(
                "file-system discovery",
                exc,
            )
            raise AssertionError("unreachable")
