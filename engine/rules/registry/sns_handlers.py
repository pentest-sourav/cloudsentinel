from typing import Any, Callable

from scanner.aws.collectors.sns import SNSDataCollector


SNS_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[SNSDataCollector], Any],
] = {
    "sns_security": SNSDataCollector.collect_security,
}
