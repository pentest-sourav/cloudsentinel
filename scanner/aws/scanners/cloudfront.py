from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.cloudfront_handlers import (
    CLOUDFRONT_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.cloudfront_registry import (
    CLOUDFRONT_RULES,
)
from scanner.aws.collectors.cloudfront import (
    CloudFrontDataCollector,
)
from scanner.aws.services.cloudfront import (
    CloudFrontService,
)


class CloudFrontScanner:
    """
    Execute Amazon CloudFront security posture rules.
    """

    def __init__(
        self,
        service: CloudFrontService,
    ):
        self.collector = CloudFrontDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=CLOUDFRONT_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=CLOUDFRONT_RULES,
            collector=self.collector,
        )
