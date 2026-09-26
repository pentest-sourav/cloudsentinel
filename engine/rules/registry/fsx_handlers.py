from scanner.aws.collectors.fsx import FSxDataCollector


def collect_fsx_file_systems(
    collector: FSxDataCollector,
) -> list[dict]:
    return collector.collect_file_systems()


FSX_DATA_SOURCE_HANDLERS = {
    "fsx_file_systems": collect_fsx_file_systems,
}
