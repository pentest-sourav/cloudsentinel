from engine.rules.registry.sns_handlers import SNS_DATA_SOURCE_HANDLERS
from scanner.aws.collectors.sns import SNSDataCollector


def test_sns_security_handler_is_registered():
    assert "sns_security" in SNS_DATA_SOURCE_HANDLERS
    assert (
        SNS_DATA_SOURCE_HANDLERS["sns_security"]
        is SNSDataCollector.collect_security
    )
