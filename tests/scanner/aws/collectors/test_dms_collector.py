from unittest.mock import Mock

from scanner.aws.collectors.dms import DMSDataCollector


def _service():
    service = Mock()

    service.describe_replication_instances.return_value = []
    service.describe_certificates.return_value = []
    service.describe_event_subscriptions.return_value = []
    service.describe_replication_subnet_groups.return_value = []
    service.describe_replication_tasks.return_value = []
    service.describe_endpoints.return_value = []

    return service


def test_replication_instance_collection():
    service = _service()

    service.describe_replication_instances.return_value = [
        {
            "ReplicationInstanceArn": "arn:ri",
            "ReplicationInstanceIdentifier": "ri",
            "PubliclyAccessible": False,
            "AutoMinorVersionUpgrade": True,
            "MultiAZ": True,
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "aws:system": "ignored",
    }

    result = DMSDataCollector(
        service
    ).collect_replication_instances()

    assert result[0]["tags"] == {
        "Environment": "prod"
    }

    assert result[0]["publicly_accessible"] is False
    assert result[0]["auto_minor_version_upgrade"] is True
    assert result[0]["multi_az"] is True


def test_system_tags_are_ignored():
    service = _service()

    service.describe_certificates.return_value = [
        {
            "CertificateArn": "arn:cert",
            "CertificateIdentifier": "cert",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system"
    }

    result = DMSDataCollector(
        service
    ).collect_certificates()

    assert result[0]["tags"] == {}
    assert result[0]["has_non_system_tags"] is False


def test_replication_task_settings_are_parsed():
    service = _service()

    service.describe_replication_tasks.return_value = [
        {
            "ReplicationTaskArn": "arn:task",
            "ReplicationTaskIdentifier": "task",
            "ReplicationTaskSettings": (
                '{"Logging": {'
                '"EnableLogging": true,'
                '"LogComponents": ['
                '{"Id":"TARGET_APPLY",'
                '"Severity":"LOGGER_SEVERITY_DEFAULT"},'
                '{"Id":"TARGET_LOAD",'
                '"Severity":"LOGGER_SEVERITY_DEBUG"},'
                '{"Id":"SOURCE_CAPTURE",'
                '"Severity":"LOGGER_SEVERITY_DEFAULT"},'
                '{"Id":"SOURCE_UNLOAD",'
                '"Severity":"LOGGER_SEVERITY_DEFAULT"}'
                ']}}'
            ),
        }
    ]

    service.list_tags_for_resource.return_value = {}

    result = DMSDataCollector(
        service
    ).collect_replication_tasks()

    assert result[0]["logging_enabled"] is True

    assert result[0]["log_components"] == {
        "TARGET_APPLY": "LOGGER_SEVERITY_DEFAULT",
        "TARGET_LOAD": "LOGGER_SEVERITY_DEBUG",
        "SOURCE_CAPTURE": "LOGGER_SEVERITY_DEFAULT",
        "SOURCE_UNLOAD": "LOGGER_SEVERITY_DEFAULT",
    }


def test_endpoint_settings_are_normalized():
    service = _service()

    service.describe_endpoints.return_value = [
        {
            "EndpointArn": "arn:mongodb",
            "EndpointIdentifier": "mongo",
            "EngineName": "mongodb",
            "SslMode": "require",
            "MongoDbSettings": {
                "AuthType": "password",
                "AuthMechanism": "scram_sha_1",
            },
        },
        {
            "EndpointArn": "arn:neptune",
            "EndpointIdentifier": "neptune",
            "EngineName": "neptune",
            "SslMode": "require",
            "NeptuneSettings": {
                "IamAuthMode": "REQUIRED",
            },
        },
    ]

    service.list_tags_for_resource.return_value = {}

    result = DMSDataCollector(
        service
    ).collect_endpoints()

    assert result[0]["engine_name"] == "mongodb"
    assert result[0]["mongo_auth_type"] == "password"

    assert result[1]["engine_name"] == "neptune"
    assert (
        result[1]["neptune_iam_auth_mode"]
        == "REQUIRED"
    )


def test_collector_caches_discovery():
    service = _service()

    service.describe_replication_instances.return_value = []

    collector = DMSDataCollector(service)

    collector.collect_replication_instances()
    collector.collect_replication_instances()

    service.describe_replication_instances.assert_called_once()
