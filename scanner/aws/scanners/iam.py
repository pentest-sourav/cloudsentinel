from engine.findings.model import Finding
from engine.rules.registry.iam_handlers import IAM_DATA_SOURCE_HANDLERS
from engine.rules.registry.iam_registry import IAM_RULES

from scanner.aws.collectors.iam import IAMDataCollector
from scanner.aws.services.iam import IAMService


class IAMScanner:
    def __init__(self, service: IAMService):
        self.collector = IAMDataCollector(service)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        for rule in IAM_RULES:
            data_source = rule["data_source"]
            collection_mode = rule["collection_mode"]

            handler = IAM_DATA_SOURCE_HANDLERS[data_source]
            collected_data = handler(self.collector)

            check = rule["check"]
            build_finding = rule["build_finding"]

            if collection_mode == "single":
                result = check(**collected_data)

                finding = build_finding(result)

                if finding is not None:
                    findings.append(finding)

            elif collection_mode == "multiple":
                for item in collected_data:
                    result = check(**item)

                    finding = build_finding(result)

                    if finding is not None:
                        findings.append(finding)

            else:
                raise ValueError(
                    f"Unsupported IAM collection mode: "
                    f"{collection_mode}"
                )

        return findings
