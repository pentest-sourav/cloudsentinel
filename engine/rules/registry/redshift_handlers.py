from scanner.aws.collectors.redshift import RedshiftDataCollector


def collect_redshift_clusters(
    collector: RedshiftDataCollector,
) -> list[dict]:
    return collector.collect_clusters()


REDSHIFT_DATA_SOURCE_HANDLERS = {
    "redshift_clusters": collect_redshift_clusters,
}
