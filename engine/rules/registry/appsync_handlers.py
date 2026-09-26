from scanner.aws.collectors.appsync import (
    AppSyncDataCollector,
)


def collect_appsync_graphql_apis(
    collector: AppSyncDataCollector,
) -> list[dict]:
    return collector.collect_graphql_apis()


APPSYNC_DATA_SOURCE_HANDLERS = {
    "appsync_graphql_apis": (
        collect_appsync_graphql_apis
    ),
}
