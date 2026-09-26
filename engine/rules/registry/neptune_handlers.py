from scanner.aws.collectors.neptune import NeptuneDataCollector


def collect_neptune_clusters(
    collector: NeptuneDataCollector,
) -> list[dict]:
    return collector.collect_clusters()


def collect_neptune_snapshots(
    collector: NeptuneDataCollector,
) -> list[dict]:
    return collector.collect_snapshots()


NEPTUNE_DATA_SOURCE_HANDLERS = {
    "neptune_clusters": collect_neptune_clusters,
    "neptune_snapshots": collect_neptune_snapshots,
}
