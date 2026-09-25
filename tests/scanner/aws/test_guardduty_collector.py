from unittest.mock import Mock

from scanner.aws.collectors.guardduty import (
    GuardDutyDataCollector,
)


def make_service():
    service = Mock()

    service.list_detectors.return_value = [
        "detector-a"
    ]

    service.get_detector.return_value = {
        "Status": "ENABLED",
        "Features": [
            {
                "Name": "S3_DATA_EVENTS",
                "Status": "ENABLED",
            },
            {
                "Name": "LAMBDA_NETWORK_LOGS",
                "Status": "DISABLED",
            },
        ],
        "UpdatedAt": "2026-09-25T00:00:00Z",
    }

    return service


def test_collect_detectors_normalizes_features():
    service = make_service()

    collector = GuardDutyDataCollector(service)

    result = collector.collect_detectors()

    assert len(result) == 1

    detector = result[0]

    assert detector["resource_id"] == "detector-a"
    assert detector["status"] == "ENABLED"

    assert detector["features"][
        "S3_DATA_EVENTS"
    ]["Status"] == "ENABLED"


def test_collector_caches_api_calls():
    service = make_service()

    collector = GuardDutyDataCollector(service)

    first = collector.collect_detectors()
    second = collector.collect_detectors()

    assert first is not second

    service.list_detectors.assert_called_once()
    service.get_detector.assert_called_once()


def test_collect_detectors_returns_disabled_state_when_no_detector_exists():
    service = Mock()
    service.list_detectors.return_value = []

    collector = GuardDutyDataCollector(service)

    detectors = collector.collect_detectors()

    assert detectors == [
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
