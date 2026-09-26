from scanner.aws.collectors.apprunner import (
    AppRunnerDataCollector,
)


def collect_apprunner_services(
    collector: AppRunnerDataCollector,
) -> list[dict]:
    return collector.collect_services()


def collect_apprunner_vpc_connectors(
    collector: AppRunnerDataCollector,
) -> list[dict]:
    return collector.collect_vpc_connectors()


APPRUNNER_DATA_SOURCE_HANDLERS = {
    "apprunner_services": collect_apprunner_services,
    "apprunner_vpc_connectors": collect_apprunner_vpc_connectors,
}
