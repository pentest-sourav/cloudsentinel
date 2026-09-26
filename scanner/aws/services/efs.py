from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class EFSService:
    """
    Read-only Amazon EFS discovery service.

    Retrieves file systems and access points required by
    CloudSentinel EFS security rules.
    """

    def __init__(self, session):
        self.efs_client = create_aws_client(
            session,
            "efs",
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
                f"AWS EFS {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during EFS "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during EFS "
            f"{operation}: {exc}"
        ) from exc

    def list_file_systems(self) -> list[dict[str, Any]]:
        file_systems: list[dict[str, Any]] = []
        marker: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxItems": 100,
                }

                if marker:
                    request["Marker"] = marker

                response = self.efs_client.describe_file_systems(
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

                next_marker = response.get(
                    "NextMarker"
                )

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return file_systems

        except Exception as exc:
            self._raise_api_error(
                "file-system discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_access_points(self) -> list[dict[str, Any]]:
        access_points: list[dict[str, Any]] = []
        marker: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 100,
                }

                if marker:
                    request["NextToken"] = marker

                response = self.efs_client.describe_access_points(
                    **request,
                )

                entries = response.get(
                    "AccessPoints",
                    [],
                )

                if isinstance(entries, list):
                    access_points.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                next_marker = response.get(
                    "NextToken"
                )

                if (
                    not isinstance(next_marker, str)
                    or not next_marker
                ):
                    break

                marker = next_marker

            return access_points

        except Exception as exc:
            self._raise_api_error(
                "access-point discovery",
                exc,
            )
            raise AssertionError("unreachable")
