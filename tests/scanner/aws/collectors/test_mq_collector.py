from unittest.mock import Mock

from scanner.aws.collectors.mq import MQDataCollector


def test_collect_brokers_normalizes_security_fields():
    service = Mock()

    service.list_broker_details.return_value = [
        {
            "BrokerId": "b-123",
            "BrokerArn": (
                "arn:aws:mq:ap-south-1:"
                "123456789012:broker:test:123"
            ),
            "BrokerName": "prod-broker",
            "EngineType": "ACTIVEMQ",
            "EngineVersion": "5.18",
            "DeploymentMode": "ACTIVE_STANDBY_MULTI_AZ",
            "BrokerState": "RUNNING",
            "PubliclyAccessible": False,
            "Logs": {
                "Audit": True,
                "AuditLogGroup": (
                    "/aws/amazonmq/broker/b-123/audit"
                ),
                "General": True,
                "GeneralLogGroup": (
                    "/aws/amazonmq/broker/b-123/general"
                ),
            },
            "Tags": {
                "Environment": "prod",
                "aws:cloudformation:stack-id": "system",
            },
        },
    ]

    collector = MQDataCollector(service)

    assert collector.collect_brokers() == [
        {
            "resource_id": "b-123",
            "resource_type": "amazonmq_broker",
            "resource_arn": (
                "arn:aws:mq:ap-south-1:"
                "123456789012:broker:test:123"
            ),
            "name": "prod-broker",
            "engine_type": "ACTIVEMQ",
            "engine_version": "5.18",
            "deployment_mode": "ACTIVE_STANDBY_MULTI_AZ",
            "broker_state": "RUNNING",
            "publicly_accessible": False,
            "logs_audit": True,
            "audit_log_group": (
                "/aws/amazonmq/broker/b-123/audit"
            ),
            "logs_general": True,
            "general_log_group": (
                "/aws/amazonmq/broker/b-123/general"
            ),
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
    ]


def test_collector_caches_brokers():
    service = Mock()
    service.list_broker_details.return_value = [
        {
            "BrokerId": "b-123",
            "EngineType": "RABBITMQ",
        },
    ]

    collector = MQDataCollector(service)

    collector.collect_brokers()
    collector.collect_brokers()

    service.list_broker_details.assert_called_once()


def test_collector_ignores_system_tags():
    service = Mock()
    service.list_broker_details.return_value = [
        {
            "BrokerId": "b-123",
            "Tags": {
                "aws:cloudformation:stack-id": "system",
            },
        },
    ]

    collector = MQDataCollector(service)

    assert collector.collect_brokers()[0]["tags"] == []
