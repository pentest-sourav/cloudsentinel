from scanner.aws.collectors.documentdb import DocumentDBDataCollector


def collect_documentdb_clusters(
    collector: DocumentDBDataCollector,
) -> list[dict]:
    return collector.collect_clusters()


def collect_documentdb_snapshots(
    collector: DocumentDBDataCollector,
) -> list[dict]:
    return collector.collect_snapshots()


DOCUMENTDB_DATA_SOURCE_HANDLERS = {
    "documentdb_clusters": collect_documentdb_clusters,
    "documentdb_snapshots": collect_documentdb_snapshots,
}
