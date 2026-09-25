from unittest.mock import Mock

import pytest

from scanner.aws.services.guardduty import (
    GuardDutyService,
)


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = GuardDutyService(session)

    return service, session, client


def test_init_creates_guardduty_client():
    service, session, client = make_service()

    assert service.guardduty_client is client
    session.client.assert_called_once()


def test_list_detectors_returns_detector_ids():
    service, _, client = make_service()

    client.list_detectors.return_value = {
        "DetectorIds": [
            "detector-a",
            "detector-b",
        ]
    }

    assert service.list_detectors() == [
        "detector-a",
        "detector-b",
    ]


def test_get_detector_returns_configuration():
    service, _, client = make_service()

    client.get_detector.return_value = {
        "Status": "ENABLED",
        "Features": [
            {
                "Name": "S3_DATA_EVENTS",
                "Status": "ENABLED",
            }
        ],
    }

    result = service.get_detector(
        "detector-a"
    )

    assert result["Status"] == "ENABLED"
    assert result["Features"][0]["Name"] == (
        "S3_DATA_EVENTS"
    )


def test_sdk_error_is_wrapped():
    service, _, client = make_service()

    client.get_detector.side_effect = Exception(
        "boom"
    )

    with pytest.raises(
        RuntimeError,
        match="Unexpected error during GuardDuty",
    ):
        service.get_detector("detector-a")
