from scanner.aws.collectors.securityhub import (
    SecurityHubDataCollector,
)


def collect_securityhub_hub(
    collector: SecurityHubDataCollector,
) -> dict:
    return collector.collect_hub()


def collect_securityhub_standards(
    collector: SecurityHubDataCollector,
) -> list[dict]:
    return collector.collect_standards()


SECURITYHUB_DATA_SOURCE_HANDLERS = {
    "securityhub_hub": collect_securityhub_hub,
    "securityhub_standards": (
        collect_securityhub_standards
    ),
}
