from unittest.mock import Mock

import pytest

from scanner.aws.services.eks import EKSService


def make_service():
    session = Mock()
    client = Mock()
    session.client.return_value = client

    service = EKSService(session)

    return service, session, client


def test_init_creates_eks_client():
    service, session, client = make_service()

    assert service.client is client
    session.client.assert_called_once()


def test_list_clusters_uses_paginator():
    service, _, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {"clusters": ["cluster-a", "cluster-b"]},
        {"clusters": ["cluster-c"]},
    ]

    client.get_paginator.return_value = paginator

    result = service.list_clusters()

    assert result == [
        "cluster-a",
        "cluster-b",
        "cluster-c",
    ]

    client.get_paginator.assert_called_once_with(
        "list_clusters"
    )


def test_describe_cluster_returns_cluster():
    service, _, client = make_service()

    client.describe_cluster.return_value = {
        "cluster": {
            "name": "cluster-a",
            "version": "1.34",
        }
    }

    result = service.describe_cluster("cluster-a")

    assert result["name"] == "cluster-a"
    assert result["version"] == "1.34"


def test_list_nodegroups_uses_cluster_name():
    service, _, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "nodegroups": [
                "ng-a",
                "ng-b",
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    result = service.list_nodegroups("cluster-a")

    assert result == ["ng-a", "ng-b"]

    paginator.paginate.assert_called_once_with(
        clusterName="cluster-a"
    )


def test_describe_nodegroup_returns_nodegroup():
    service, _, client = make_service()

    client.describe_nodegroup.return_value = {
        "nodegroup": {
            "nodegroupName": "ng-a",
            "version": "1.34",
        }
    }

    result = service.describe_nodegroup(
        "cluster-a",
        "ng-a",
    )

    assert result["nodegroupName"] == "ng-a"
    assert result["version"] == "1.34"


def test_list_identity_provider_configs_uses_cluster():
    service, _, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "identityProviderConfigs": [
                {
                    "type": "oidc",
                    "name": "github",
                }
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    result = (
        service.list_identity_provider_configs(
            "cluster-a"
        )
    )

    assert result == [
        {
            "type": "oidc",
            "name": "github",
        }
    ]


def test_describe_identity_provider_config_returns_detail():
    service, _, client = make_service()

    client.describe_identity_provider_config.return_value = {
        "identityProviderConfig": {
            "oidc": {
                "identityProviderConfigName": "github",
                "identityProviderConfigArn": "arn:oidc",
                "tags": {
                    "Owner": "security",
                },
            }
        }
    }

    result = (
        service.describe_identity_provider_config(
            cluster_name="cluster-a",
            provider_type="oidc",
            provider_name="github",
        )
    )

    assert result["oidc"]["identityProviderConfigName"] == (
        "github"
    )
    assert result["oidc"]["tags"] == {
        "Owner": "security"
    }


def test_invalid_sdk_error_is_wrapped():
    service, _, client = make_service()

    client.describe_cluster.side_effect = Exception(
        "boom"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during EKS",
    ):
        service.describe_cluster("cluster-a")
