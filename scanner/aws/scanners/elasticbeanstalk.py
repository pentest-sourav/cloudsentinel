from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.elasticbeanstalk_handlers import (
    ELASTICBEANSTALK_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.elasticbeanstalk_registry import (
    ELASTICBEANSTALK_RULES,
)
from scanner.aws.collectors.elasticbeanstalk import (
    ElasticBeanstalkDataCollector,
)
from scanner.aws.services.elasticbeanstalk import (
    ElasticBeanstalkService,
)


class ElasticBeanstalkScanner:
    """
    Execute AWS Elastic Beanstalk security posture rules.
    """

    def __init__(
        self,
        service: ElasticBeanstalkService,
    ):
        self.collector = ElasticBeanstalkDataCollector(
            service,
        )

        self.executor = RuleExecutor(
            handlers=ELASTICBEANSTALK_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ELASTICBEANSTALK_RULES,
            collector=self.collector,
        )
