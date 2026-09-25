from unittest.mock import Mock

from scanner.aws.collectors.eks import EKSDataCollector


def make_service():
    service = Mock()

    service.list_clusters.return_value = [
        "cluster-a",
    ]

    service.describe_cluster.return_value = {
        "name": "cluster-a",
        "arn": "arn:aws:eks:ap-south-1:123:cluster/cluster-a",
        "version": "1.34",
        "resourcesVpcConfig": {
            "endpointPublicAccess": False,
            "endpointPrivateAccess": True,
            "publicAccessCidrs": [
                "10.0.0.0/8"
            ],
        },
        "logging": {
            "clusterLogging": [
                {
                    "types": ["audit"],
                    "enabled": True,
                }
            ]
        },
        "tags": {
            "Environment": "prod",
        },
    }

    service.list_nodegroups.return_value = [
        "ng-a",
    ]

    service.describe_nodegroup.return_value = {
        "nodegroupName": "ng-a",
        "nodegroupArn": (
            "arn:aws:eks:ap-south-1:123:"
            "nodegroup/cluster-a/ng-a/abc"
        ),
        "clusterName": "cluster-a",
        "version": "1.34",
        "status": "ACTIVE",
        "tags": {
            "Environment": "prod",
        },
    }

    service.list_identity_provider_configs.return_value = [
        {
            "type": "oidc",
            "name": "github",
        }
    ]

    service.describe_identity_provider_config.return_value = {
        "oidc": {
            "identityProviderConfigName": "github",
            "identityProviderConfigArn": (
                "arn:aws:eks:ap-south-1:123:"
                "identityproviderconfig/cluster-a/github"
            ),
            "clusterName": "cluster-a",
            "status": "ACTIVE",
            "tags": {
                "Owner": "security",
            },
        }
    }

    return service


def test_collect_clusters_normalizes_security_fields():
    service = make_service()
    collector = EKSDataCollector(service)

    result = collector.collect_clusters()

    assert len(result) == 1

    cluster = result[0]

    assert cluster["resource_id"] == "cluster-a"
    assert cluster["version"] == "1.34"
    assert cluster["endpoint_public_access"] is False
    assert cluster["endpoint_private_access"] is True
    assert cluster["cluster_logging"][0]["types"] == [
        "audit"
    ]
    assert cluster["tags"] == {
        "Environment": "prod"
    }


def test_collect_nodegroups_normalizes_version():
    service = make_service()
    collector = EKSDataCollector(service)

    result = collector.collect_nodegroups()

    assert len(result) == 1
    assert result[0]["nodegroup_name"] == "ng-a"
    assert result[0]["version"] == "1.34"


def test_collect_identity_provider_configs_normalizes_tags():
    service = make_service()
    collector = EKSDataCollector(service)

    result = (
        collector.collect_identity_provider_configs()
    )

    assert len(result) == 1
    assert result[0]["provider_name"] == "github"
    assert result[0]["provider_type"] == "oidc"
    assert result[0]["tags"] == {
        "Owner": "security"
    }


def test_collector_caches_cluster_collection():
    service = make_service()
    collector = EKSDataCollector(service)

    first = collector.collect_clusters()
    second = collector.collect_clusters()

    assert first is second
    service.list_clusters.assert_called_once()
    service.describe_cluster.assert_called_once_with(
        "cluster-a"
    )
