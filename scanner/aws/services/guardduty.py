from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class GuardDutyService:
    """
    Read-only Amazon GuardDuty discovery service.

    This service retrieves detector configuration only.
    It never enables, disables, or mutates GuardDuty.
    """

    def __init__(self, session):
        self.session = session
        self.guardduty_client = create_aws_client(
            session,
            "guardduty",
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
                f"GuardDuty {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during GuardDuty "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during GuardDuty "
            f"{operation}: {exc}"
        ) from exc

    def list_detectors(self) -> list[str]:
        try:
            response = self.guardduty_client.list_detectors()

            detector_ids = response.get(
                "DetectorIds",
                [],
            )

            if not isinstance(detector_ids, list):
                return []

            return [
                detector_id
                for detector_id in detector_ids
                if isinstance(detector_id, str)
                and detector_id
            ]

        except Exception as exc:
            self._raise_api_error(
                "detector discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_detector(
        self,
        detector_id: str,
    ) -> dict[str, Any]:
        try:
            response = self.guardduty_client.get_detector(
                DetectorId=detector_id,
            )

            if not isinstance(response, dict):
                return {}

            return response

        except Exception as exc:
            self._raise_api_error(
                "detector configuration",
                exc,
            )
            raise AssertionError("unreachable")
