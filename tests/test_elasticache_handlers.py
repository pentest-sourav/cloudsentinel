from unittest.mock import Mock

from engine.rules.registry.elasticache_handlers import (
    ELASTICACHE_DATA_SOURCE_HANDLERS,
)


def test_elasticache_handlers_cover_both_data_sources():
    assert set(
        ELASTICACHE_DATA_SOURCE_HANDLERS
    ) == {
        "elasticache_cache_clusters",
        "elasticache_replication_groups",
    }


def test_elasticache_handlers_are_callable():
    assert callable(
        ELASTICACHE_DATA_SOURCE_HANDLERS[
            "elasticache_cache_clusters"
        ]
    )

    assert callable(
        ELASTICACHE_DATA_SOURCE_HANDLERS[
            "elasticache_replication_groups"
        ]
    )


def test_elasticache_cache_cluster_handler_collects_data():
    collector = Mock()
    collector.collect_cache_clusters.return_value = [
        {"cache_cluster_id": "cluster-1"}
    ]

    handler = ELASTICACHE_DATA_SOURCE_HANDLERS[
        "elasticache_cache_clusters"
    ]

    result = handler(collector)

    assert result == [
        {"cache_cluster_id": "cluster-1"}
    ]
    collector.collect_cache_clusters.assert_called_once()


def test_elasticache_replication_group_handler_collects_data():
    collector = Mock()
    collector.collect_replication_groups.return_value = [
        {"replication_group_id": "group-1"}
    ]

    handler = ELASTICACHE_DATA_SOURCE_HANDLERS[
        "elasticache_replication_groups"
    ]

    result = handler(collector)

    assert result == [
        {"replication_group_id": "group-1"}
    ]
    collector.collect_replication_groups.assert_called_once()
