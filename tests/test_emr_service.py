from unittest.mock import Mock

import pytest

from scanner.aws.services.emr import EMRService


def test_list_clusters_uses_paginator():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {"Clusters": [{"Id": "j-1"}]},
        {"Clusters": [{"Id": "j-2"}]},
    ]

    client.get_paginator.return_value = paginator

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.emr.create_aws_client",
            Mock(return_value=client),
        )

        service = EMRService(session)
        result = service.list_clusters()

    assert result == [
        {"Id": "j-1"},
        {"Id": "j-2"},
    ]
    client.get_paginator.assert_called_once_with(
        "list_clusters"
    )


def test_list_master_instances_filters_master_group():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {"Instances": [{"Id": "i-master"}]}
    ]
    client.get_paginator.return_value = paginator

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.emr.create_aws_client",
            Mock(return_value=client),
        )

        service = EMRService(session)
        result = service.list_master_instances("j-1")

    assert result == [{"Id": "i-master"}]
    paginator.paginate.assert_called_once_with(
        ClusterId="j-1",
        InstanceGroupTypes=["MASTER"],
    )


def test_describe_cluster_returns_cluster():
    session = Mock()
    client = Mock()
    client.describe_cluster.return_value = {
        "Cluster": {"Id": "j-1"}
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.emr.create_aws_client",
            Mock(return_value=client),
        )

        service = EMRService(session)
        result = service.describe_cluster("j-1")

    assert result == {"Id": "j-1"}


def test_empty_cluster_id_is_safe():
    session = Mock()
    client = Mock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.emr.create_aws_client",
            Mock(return_value=client),
        )

        service = EMRService(session)
        assert service.describe_cluster("") == {}
        assert service.list_master_instances("") == []

    client.describe_cluster.assert_not_called()


def test_get_block_public_access_configuration():
    session = Mock()
    client = Mock()
    client.get_block_public_access_configuration.return_value = {
        "BlockPublicAccessConfiguration": {
            "BlockPublicSecurityGroupRules": True
        }
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.emr.create_aws_client",
            Mock(return_value=client),
        )

        service = EMRService(session)
        result = service.get_block_public_access_configuration()

    assert result["BlockPublicSecurityGroupRules"] is True


def test_list_security_configurations_uses_paginator():
    session = Mock()
    client = Mock()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "SecurityConfigurations": [
                {"Name": "secure-emr"}
            ]
        }
    ]
    client.get_paginator.return_value = paginator

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.emr.create_aws_client",
            Mock(return_value=client),
        )

        service = EMRService(session)
        result = service.list_security_configurations()

    assert result == [{"Name": "secure-emr"}]
