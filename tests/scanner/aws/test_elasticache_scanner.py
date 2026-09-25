from unittest.mock import Mock

from scanner.aws.scanners.elasticache import ElastiCacheScanner


def test_elasticache_scanner_executes_all_rules_without_findings():
    service = Mock()

    service.describe_cache_clusters.return_value = [
        {
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
            "CacheSubnetGroupName": "custom",
            "NumCacheNodes": 2,
        }
    ]

    service.describe_replication_groups.return_value = [
        {
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
            "CacheSubnetGroupName": "custom",
            "SnapshotRetentionLimit": 7,
            "NumNodeGroups": 1,
            "ReplicasPerNodeGroup": 2,
        }
    ]

    scanner = ElastiCacheScanner(service)

    findings = scanner.scan()

    assert findings == []
    service.describe_cache_clusters.assert_called_once()
    service.describe_replication_groups.assert_called_once()
