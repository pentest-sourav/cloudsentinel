from engine.rules.registry.eventbridge_handlers import (
    EVENTBRIDGE_DATA_SOURCE_HANDLERS,
    collect_eventbridge_endpoints,
    collect_eventbridge_event_buses,
)


def test_eventbridge_handlers_are_registered():
    assert (
        "eventbridge_event_buses"
        in EVENTBRIDGE_DATA_SOURCE_HANDLERS
    )

    assert (
        "eventbridge_global_endpoints"
        in EVENTBRIDGE_DATA_SOURCE_HANDLERS
    )

    assert (
        EVENTBRIDGE_DATA_SOURCE_HANDLERS[
            "eventbridge_event_buses"
        ]
        is collect_eventbridge_event_buses
    )

    assert (
        EVENTBRIDGE_DATA_SOURCE_HANDLERS[
            "eventbridge_global_endpoints"
        ]
        is collect_eventbridge_endpoints
    )
