from unittest.mock import Mock, patch

from scanner.aws.scanners.elasticbeanstalk import (
    ElasticBeanstalkScanner,
)


def test_scan_executes_elasticbeanstalk_registry():
    service = Mock()

    with patch(
        "scanner.aws.scanners.elasticbeanstalk.RuleExecutor"
    ) as executor_class:
        executor = executor_class.return_value
        executor.execute_registry.return_value = [
            Mock(rule_id="CS-AWS-ELASTICBEANSTALK-001")
        ]

        scanner = ElasticBeanstalkScanner(service)
        findings = scanner.scan()

    assert len(findings) == 1
    assert (
        findings[0].rule_id
        == "CS-AWS-ELASTICBEANSTALK-001"
    )

    executor.execute_registry.assert_called_once()
