from unittest.mock import Mock

from scanner.aws.scanners.mq import MQScanner


def test_mq_scanner_executes_registered_rules():
    service = Mock()

    service.list_broker_details.return_value = [
        {
            "BrokerId": "b-activemq",
            "BrokerArn": "arn:aws:mq:example",
            "BrokerName": "active",
            "EngineType": "ACTIVEMQ",
            "DeploymentMode": "SINGLE_INSTANCE",
            "Logs": {
                "Audit": False,
            },
            "Tags": {},
        },
        {
            "BrokerId": "b-rabbitmq",
            "BrokerName": "rabbit",
            "EngineType": "RABBITMQ",
            "DeploymentMode": "SINGLE_INSTANCE",
            "Logs": {},
            "Tags": {},
        },
    ]

    findings = MQScanner(service).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-MQ-002",
        "CS-AWS-MQ-004",
        "CS-AWS-MQ-005",
        "CS-AWS-MQ-006",
    }
