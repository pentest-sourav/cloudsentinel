from typing import Any, Callable

from scanner.aws.collectors.elasticache import (
    ElastiCacheDataCollector,
)


def collect_elasticache_cache_clusters(
    collector: ElastiCacheDataCollector,
) -> list[dict]:
    return collector.collect_cache_clusters()


def collect_elasticache_replication_groups(
    collector: ElastiCacheDataCollector,
) -> list[dict]:
    return collector.collect_replication_groups()


ELASTICACHE_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[ElastiCacheDataCollector], Any],
] = {
    "elasticache_cache_clusters": (
        collect_elasticache_cache_clusters
    ),
    "elasticache_replication_groups": (
        collect_elasticache_replication_groups
    ),
}
