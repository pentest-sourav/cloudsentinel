from scanner.aws.collectors.inspector import (
    InspectorDataCollector,
)


def collect_inspector_account(
    collector: InspectorDataCollector,
) -> list[dict]:
    return collector.collect_account_status()


INSPECTOR_DATA_SOURCE_HANDLERS = {
    "inspector_account": collect_inspector_account,
}
