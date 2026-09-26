from scanner.aws.collectors.athena import AthenaDataCollector


def collect_athena_data_catalogs(
    collector: AthenaDataCollector,
) -> list[dict]:
    return collector.collect_data_catalogs()


def collect_athena_workgroups(
    collector: AthenaDataCollector,
) -> list[dict]:
    return collector.collect_workgroups()


ATHENA_DATA_SOURCE_HANDLERS = {
    "athena_data_catalogs": collect_athena_data_catalogs,
    "athena_workgroups": collect_athena_workgroups,
}
