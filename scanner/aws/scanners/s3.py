from engine.findings.model import Finding
from engine.rules.registry.s3_registry import S3_RULES
from scanner.aws.services.s3 import S3Service


class S3Scanner:
    def __init__(self, service: S3Service):
        self.service = service

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        buckets = self.service.list_buckets()

        for bucket in buckets:
            bucket_name = bucket["name"]

            for rule in S3_RULES:
                service_method_name = rule["service_method"]
                configuration_argument = rule["configuration_argument"]

                service_method = getattr(
                    self.service,
                    service_method_name,
                )

                configuration = service_method(
                    bucket_name
                )

                check = rule["check"]
                build_finding = rule["build_finding"]

                result = check(
                    bucket_name=bucket_name,
                    **{
                        configuration_argument: configuration,
                    },
                )

                finding = build_finding(result)

                if finding is not None:
                    findings.append(finding)

        return findings
