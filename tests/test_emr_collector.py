from unittest.mock import Mock

from scanner.aws.collectors.emr import EMRDataCollector


def test_collect_clusters_normalizes_master_public_ip():
    service = Mock()

    service.list_clusters.return_value = [
        {
            "Id": "j-1",
            "Name": "cluster-one",
            "ClusterArn": "arn:aws:elasticmapreduce:cluster/j-1",
            "Status": {"State": "WAITING"},
        }
    ]

    service.list_master_instances.return_value = [
        {
            "Id": "i-master",
            "PublicIpAddress": "1.2.3.4",
        }
    ]

    collector = EMRDataCollector(service)

    result = collector.collect_clusters()

    assert result == [
        {
            "cluster_id": "j-1",
            "cluster_arn": (
                "arn:aws:elasticmapreduce:cluster/j-1"
            ),
            "cluster_name": "cluster-one",
            "cluster_status": "WAITING",
            "master_public_ip": "1.2.3.4",
            "master_has_public_ip": True,
            "master_instance_count": 1,
        }
    ]


def test_collect_clusters_does_not_fail_when_master_ip_missing():
    service = Mock()

    service.list_clusters.return_value = [
        {"Id": "j-1"}
    ]
    service.list_master_instances.return_value = [
        {"Id": "i-master"}
    ]

    collector = EMRDataCollector(service)

    result = collector.collect_clusters()

    assert result[0]["master_has_public_ip"] is False
    assert result[0]["master_public_ip"] is None


def test_collect_clusters_missing_master_instances_is_unknown():
    service = Mock()

    service.list_clusters.return_value = [
        {"Id": "j-1"}
    ]
    service.list_master_instances.return_value = []

    collector = EMRDataCollector(service)

    result = collector.collect_clusters()

    assert result[0]["master_has_public_ip"] is None


def test_collect_clusters_caches_master_instances():
    service = Mock()

    service.list_clusters.return_value = [
        {"Id": "j-1"}
    ]
    service.list_master_instances.return_value = [
        {"Id": "i-master"}
    ]

    collector = EMRDataCollector(service)

    collector.collect_clusters()
    collector.collect_clusters()

    service.list_clusters.assert_called_once()
    service.list_master_instances.assert_called_once_with(
        "j-1"
    )


def test_collect_security_configurations_parses_json():
    service = Mock()

    service.list_security_configurations.return_value = [
        {"Name": "secure-emr"}
    ]

    service.get_security_configuration.return_value = {
        "Name": "secure-emr",
        "SecurityConfiguration": (
            '{"EncryptionConfiguration": {'
            '"EnableAtRestEncryption": true,'
            '"EnableInTransitEncryption": true'
            '}}'
        ),
    }

    collector = EMRDataCollector(service)

    result = collector.collect_security_configurations()

    assert result == [
        {
            "security_configuration_name": "secure-emr",
            "security_configuration_arn": None,
            "enable_at_rest_encryption": True,
            "enable_in_transit_encryption": True,
        }
    ]


def test_collect_security_configurations_missing_encryption_is_unknown():
    service = Mock()

    service.list_security_configurations.return_value = [
        {"Name": "unknown-emr"}
    ]

    service.get_security_configuration.return_value = {
        "Name": "unknown-emr",
        "SecurityConfiguration": "{}",
    }

    collector = EMRDataCollector(service)

    result = collector.collect_security_configurations()

    assert result[0]["enable_at_rest_encryption"] is None
    assert result[0]["enable_in_transit_encryption"] is None


def test_collect_security_configurations_caches_details():
    service = Mock()

    service.list_security_configurations.return_value = [
        {"Name": "secure-emr"}
    ]
    service.get_security_configuration.return_value = {
        "SecurityConfiguration": (
            '{"EncryptionConfiguration": {'
            '"EnableAtRestEncryption": true,'
            '"EnableInTransitEncryption": true'
            '}}'
        )
    }

    collector = EMRDataCollector(service)

    collector.collect_security_configurations()
    collector.collect_security_configurations()

    service.list_security_configurations.assert_called_once()
    service.get_security_configuration.assert_called_once_with(
        "secure-emr"
    )


def test_collect_block_public_access_secure_port_22_exception():
    service = Mock()

    service.get_block_public_access_configuration.return_value = {
        "BlockPublicSecurityGroupRules": True,
        "PermittedPublicSecurityGroupRuleRanges": [
            "22"
        ],
    }

    collector = EMRDataCollector(service)

    result = collector.collect_block_public_access()

    assert result == [
        {
            "block_public_security_group_rules": True,
            "permitted_public_security_group_rule_ranges": [
                "22"
            ],
            "has_unsafe_public_access_exception": False,
        }
    ]


def test_collect_block_public_access_flags_unsafe_exception():
    service = Mock()

    service.get_block_public_access_configuration.return_value = {
        "BlockPublicSecurityGroupRules": True,
        "PermittedPublicSecurityGroupRuleRanges": [
            "22",
            "443",
        ],
    }

    collector = EMRDataCollector(service)

    result = collector.collect_block_public_access()

    assert result[0]["has_unsafe_public_access_exception"] is True


def test_collect_block_public_access_disabled():
    service = Mock()

    service.get_block_public_access_configuration.return_value = {
        "BlockPublicSecurityGroupRules": False,
        "PermittedPublicSecurityGroupRuleRanges": [],
    }

    collector = EMRDataCollector(service)

    result = collector.collect_block_public_access()

    assert result[0]["block_public_security_group_rules"] is False
