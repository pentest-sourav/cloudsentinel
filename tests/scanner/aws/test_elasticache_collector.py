from unittest.mock import Mock

from scanner.aws.collectors.elasticache import (
    ElastiCacheDataCollector,
)


def test_collect_cache_clusters_normalizes_resources():
    service = Mock()

    raw_cluster = {
        "CacheClusterId": "cluster-1",
        "ARN": (
            "arn:aws:elasticache:ap-south-1:"
            "123456789012:cluster:cluster-1"
        ),
        "Engine": "redis",
        "EngineVersion": "7.1",
        "CacheClusterStatus": "available",
        "AutoMinorVersionUpgrade": True,
        "SnapshotRetentionLimit": 7,
        "CacheSubnetGroupName": "custom-subnet-group",
        "NumCacheNodes": 2,
    }

    service.describe_cache_clusters.return_value = [
        raw_cluster
    ]

    collector = ElastiCacheDataCollector(service)

    result = collector.collect_cache_clusters()

    assert result == [
        {
            "resource_kind": "cache_cluster",
            "resource_id": "cluster-1",
            "cache_cluster_id": "cluster-1",
            "resource_arn": (
                "arn:aws:elasticache:ap-south-1:"
                "123456789012:cluster:cluster-1"
            ),
            "engine": "redis",
            "engine_version": "7.1",
            "cache_cluster_status": "available",
            "auto_minor_version_upgrade": True,
            "snapshot_retention_limit": 7,
            "cache_subnet_group_name": "custom-subnet-group",
            "num_cache_nodes": 2,
            "resource": raw_cluster,
        }
    ]


def test_collect_replication_groups_normalizes_resources():
    service = Mock()

    raw_group = {
        "ReplicationGroupId": "group-1",
        "ARN": (
            "arn:aws:elasticache:ap-south-1:"
            "123456789012:replicationgroup:group-1"
        ),
        "Engine": "redis",
        "EngineVersion": "7.1",
        "Status": "available",
        "AutomaticFailover": "enabled",
        "MultiAZ": "enabled",
        "TransitEncryptionEnabled": True,
        "AtRestEncryptionEnabled": True,
        "AuthTokenEnabled": True,
        "CacheSubnetGroupName": "custom-subnet-group",
        "SnapshotRetentionLimit": 7,
        "NumNodeGroups": 1,
        "ReplicasPerNodeGroup": 2,
    }

    service.describe_replication_groups.return_value = [
        raw_group
    ]

    collector = ElastiCacheDataCollector(service)

    result = collector.collect_replication_groups()

    assert result[0]["resource_kind"] == "replication_group"
    assert result[0]["resource_id"] == "group-1"
    assert result[0]["replication_group_id"] == "group-1"
    assert result[0]["resource"] is raw_group
    assert result[0]["automatic_failover"] == "enabled"
    assert result[0]["transit_encryption_enabled"] is True
    assert result[0]["at_rest_encryption_enabled"] is True
    assert result[0]["auth_token_enabled"] is True


def test_collector_caches_cache_clusters():
    service = Mock()
    service.describe_cache_clusters.return_value = []

    collector = ElastiCacheDataCollector(service)

    assert collector.collect_cache_clusters() == []
    assert collector.collect_cache_clusters() == []

    service.describe_cache_clusters.assert_called_once()


def test_collector_caches_replication_groups():
    service = Mock()
    service.describe_replication_groups.return_value = []

    collector = ElastiCacheDataCollector(service)

    assert collector.collect_replication_groups() == []
    assert collector.collect_replication_groups() == []

    service.describe_replication_groups.assert_called_once()
