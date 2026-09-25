from engine.rules.registry.opensearch_handlers import (
    OPENSEARCH_DATA_SOURCE_HANDLERS,
    collect_opensearch_domains,
)


def test_opensearch_handlers_are_registered():
    assert (
        "opensearch_domains"
        in OPENSEARCH_DATA_SOURCE_HANDLERS
    )

    assert (
        OPENSEARCH_DATA_SOURCE_HANDLERS[
            "opensearch_domains"
        ]
        is collect_opensearch_domains
    )
