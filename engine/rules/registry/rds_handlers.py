from scanner.aws.collectors.rds import RDSDataCollector


def collect_rds_instances(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_instances()


def collect_rds_clusters(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_clusters()


def collect_rds_snapshots(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_snapshots()


def collect_rds_cluster_snapshots(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_cluster_snapshots()


def collect_rds_event_subscriptions(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_event_subscriptions()


def collect_rds_proxies(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_proxies()


def collect_rds_subnet_groups(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_subnet_groups()


def collect_rds_parameter_groups(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_parameter_groups()


def collect_rds_security_groups(
    collector: RDSDataCollector,
) -> list[dict]:
    return collector.collect_security_groups()


RDS_DATA_SOURCE_HANDLERS = {
    "rds_instances": collect_rds_instances,
    "rds_clusters": collect_rds_clusters,
    "rds_snapshots": collect_rds_snapshots,
    "rds_cluster_snapshots": collect_rds_cluster_snapshots,
    "rds_event_subscriptions": collect_rds_event_subscriptions,
    "rds_proxies": collect_rds_proxies,
    "rds_subnet_groups": collect_rds_subnet_groups,
    "rds_parameter_groups": collect_rds_parameter_groups,
    "rds_security_groups": collect_rds_security_groups,
}
