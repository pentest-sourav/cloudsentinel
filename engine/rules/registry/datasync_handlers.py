from scanner.aws.collectors.datasync import (
    DataSyncDataCollector,
)


def collect_datasync_tasks(
    collector: DataSyncDataCollector,
) -> list[dict]:
    return collector.collect_tasks()


DATASYNC_DATA_SOURCE_HANDLERS = {
    "tasks": collect_datasync_tasks,
}
