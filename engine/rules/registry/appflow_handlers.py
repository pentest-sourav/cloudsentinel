from scanner.aws.collectors.appflow import (
    AppFlowDataCollector,
)


def collect_appflow_flows(
    collector: AppFlowDataCollector,
) -> list[dict]:
    return collector.collect_flows()


APPFLOW_DATA_SOURCE_HANDLERS = {
    "appflow_flows": collect_appflow_flows,
}
