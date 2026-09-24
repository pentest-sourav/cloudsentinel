from engine.rules.registry.dynamodb_handlers import (
    DYNAMODB_DATA_SOURCE_HANDLERS,
    collect_dynamodb_dax_clusters,
    collect_dynamodb_tables,
)


def test_dynamodb_handlers_are_registered():
    assert (
        "dynamodb_tables"
        in DYNAMODB_DATA_SOURCE_HANDLERS
    )

    assert (
        "dynamodb_dax_clusters"
        in DYNAMODB_DATA_SOURCE_HANDLERS
    )

    assert (
        DYNAMODB_DATA_SOURCE_HANDLERS[
            "dynamodb_tables"
        ]
        is collect_dynamodb_tables
    )

    assert (
        DYNAMODB_DATA_SOURCE_HANDLERS[
            "dynamodb_dax_clusters"
        ]
        is collect_dynamodb_dax_clusters
    )
