from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.codebuild_handlers import (
    CODEBUILD_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.codebuild_registry import (
    CODEBUILD_RULES,
)

from scanner.aws.collectors.codebuild import (
    CodeBuildDataCollector,
)
from scanner.aws.services.codebuild import (
    CodeBuildService,
)


class CodeBuildScanner:
    """
    Runs registered AWS CodeBuild security rules.
    """

    def __init__(
        self,
        service: CodeBuildService,
    ):
        self.collector = CodeBuildDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=CODEBUILD_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=CODEBUILD_RULES,
            collector=self.collector,
        )
