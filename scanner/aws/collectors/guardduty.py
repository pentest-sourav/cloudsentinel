from typing import Any

from scanner.aws.services.guardduty import GuardDutyService


class GuardDutyDataCollector:
    """
    Normalize GuardDuty detector configuration for
    CloudSentinel security rules.
    """

    def __init__(
        self,
        service: GuardDutyService,
    ):
        self.service = service

        self._detectors_cache: (
            list[str] | None
        ) = None

        self._details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def _get_detector_ids(self) -> list[str]:
        if self._detectors_cache is None:
            self._detectors_cache = (
                self.service.list_detectors()
            )

        return self._detectors_cache

    def _get_detector(
        self,
        detector_id: str,
    ) -> dict[str, Any]:
        if detector_id not in self._details_cache:
            self._details_cache[
                detector_id
            ] = self.service.get_detector(
                detector_id
            )

        return self._details_cache[detector_id]

    @staticmethod
    def _normalize_features(
        features: Any,
    ) -> dict[str, dict[str, Any]]:
        if not isinstance(features, list):
            return {}

        normalized: dict[
            str,
            dict[str, Any],
        ] = {}

        for feature in features:
            if not isinstance(feature, dict):
                continue

            name = feature.get("Name")

            if not isinstance(name, str) or not name:
                continue

            normalized[name] = feature

        return normalized

    def collect_detectors(
        self,
    ) -> list[dict[str, Any]]:
        detector_ids = self._get_detector_ids()

        if not detector_ids:
            return [
                {
                    "resource_id": "guardduty",
                    "detector_id": None,
                    "status": "DISABLED",
                    "features": {},
                    "service_role": None,
                    "updated_at": None,
                    "data_sources": {},
                    "resource": {},
                }
            ]

        detectors: list[dict[str, Any]] = []

        for detector_id in detector_ids:
            details = self._get_detector(
                detector_id
            )

            if not details:
                continue

            detectors.append(
                {
                    "resource_id": detector_id,
                    "detector_id": detector_id,
                    "status": details.get(
                        "Status"
                    ),
                    "features": self._normalize_features(
                        details.get("Features")
                    ),
                    "service_role": details.get(
                        "ServiceRole"
                    ),
                    "updated_at": details.get(
                        "UpdatedAt"
                    ),
                    "data_sources": details.get(
                        "DataSources",
                        {},
                    ),
                    "resource": details,
                }
            )

        return detectors
