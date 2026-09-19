from scanner.aws.collectors.cloudtrail import CloudTrailDataCollector
from scanner.aws.services.cloudtrail import CloudTrailService

from engine.rules.aws.cloudtrail.handlers import (
    CLOUDTRAIL_DATA_SOURCE_HANDLERS,
)
from engine.rules.aws.cloudtrail.registry import CLOUDTRAIL_RULES
from engine.rules.executor import RuleExecutor


class CloudTrailScanner:
    """
    Scans AWS CloudTrail using registered security rules.
    """

    def __init__(self, service: CloudTrailService):
        self.collector = CloudTrailDataCollector(service)

        self.executor = RuleExecutor(
            handlers=CLOUDTRAIL_DATA_SOURCE_HANDLERS
        )

    def scan(self) -> list:
        return self.executor.execute_registry(
            registry=CLOUDTRAIL_RULES,
            collector=self.collector,
        )
