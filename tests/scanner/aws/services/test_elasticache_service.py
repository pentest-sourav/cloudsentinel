from unittest.mock import Mock

import pytest

from scanner.aws.services.elasticache import ElastiCacheService


def test_describe_cache_clusters_paginates():
    session = Mock()
    client = Mock()

    client.describe_cache_clusters.side_effect = [
        {
            "CacheClusters": [
                {"CacheClusterId": "cluster-1"},
            ],
            "Marker": "page-2",
        },
        {
            "CacheClusters": [
                {"CacheClusterId": "cluster-2"},
            ],
        },
    ]

    service = ElastiCacheService.__new__(ElastiCacheService)
    service.session = session
    service.elasticache_client = client

    result = service.describe_cache_clusters()

    assert result == [
        {"CacheClusterId": "cluster-1"},
        {"CacheClusterId": "cluster-2"},
    ]

    assert client.describe_cache_clusters.call_count == 2


def test_describe_replication_groups_paginates():
    session = Mock()
    client = Mock()

    client.describe_replication_groups.side_effect = [
        {
            "ReplicationGroups": [
                {"ReplicationGroupId": "group-1"},
            ],
            "Marker": "page-2",
        },
        {
            "ReplicationGroups": [
                {"ReplicationGroupId": "group-2"},
            ],
        },
    ]

    service = ElastiCacheService.__new__(ElastiCacheService)
    service.session = session
    service.elasticache_client = client

    result = service.describe_replication_groups()

    assert result == [
        {"ReplicationGroupId": "group-1"},
        {"ReplicationGroupId": "group-2"},
    ]

    assert client.describe_replication_groups.call_count == 2


def test_describe_cache_clusters_returns_empty_when_response_has_no_clusters():
    client = Mock()
    client.describe_cache_clusters.return_value = {}

    service = ElastiCacheService.__new__(ElastiCacheService)
    service.session = Mock()
    service.elasticache_client = client

    assert service.describe_cache_clusters() == []


def test_describe_replication_groups_returns_empty_when_response_has_no_groups():
    client = Mock()
    client.describe_replication_groups.return_value = {}

    service = ElastiCacheService.__new__(ElastiCacheService)
    service.session = Mock()
    service.elasticache_client = client

    assert service.describe_replication_groups() == []
