from scanner.aws.collectors.macie import (
    MacieDataCollector,
)


def collect_macie_account(
    collector: MacieDataCollector,
) -> list[dict]:
    return collector.collect_account_configuration()


MACIE_DATA_SOURCE_HANDLERS = {
    "macie_account": collect_macie_account,
}
