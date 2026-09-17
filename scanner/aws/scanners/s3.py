from engine.findings.model import Finding
from engine.rules.registry.s3_handlers import S3_DATA_SOURCE_HANDLERS
from engine.rules.registry.s3_registry import S3_RULES

from scanner.aws.collectors.s3 import S3DataCollector
from scanner.aws.services.s3 import S3Service


class S3Scanner:
    def __init__(self, service: S3Service):
        self.collector = S3DataCollector(service)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        for rule in S3_RULES:
            data_source = rule.data_source
            collection_mode = rule.collection_mode

            handler = S3_DATA_SOURCE_HANDLERS[data_source]
            collected_data = handler(self.collector)

            check = rule.check
            build_finding = rule.build_finding

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
                    f"Unsupported S3 collection mode: {collection_mode}"
                )

        return findings
