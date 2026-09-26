from scanner.aws.collectors.dms import DMSDataCollector


def collect_dms_replication_instances(
    collector: DMSDataCollector,
):
    return collector.collect_replication_instances()


def collect_dms_certificates(
    collector: DMSDataCollector,
):
    return collector.collect_certificates()


def collect_dms_event_subscriptions(
    collector: DMSDataCollector,
):
    return collector.collect_event_subscriptions()


def collect_dms_replication_subnet_groups(
    collector: DMSDataCollector,
):
    return collector.collect_replication_subnet_groups()


def collect_dms_replication_tasks(
    collector: DMSDataCollector,
):
    return collector.collect_replication_tasks()


def collect_dms_endpoints(
    collector: DMSDataCollector,
):
    return collector.collect_endpoints()


DMS_DATA_SOURCE_HANDLERS = {
    "dms_replication_instances": (
        collect_dms_replication_instances
    ),
    "dms_certificates": collect_dms_certificates,
    "dms_event_subscriptions": (
        collect_dms_event_subscriptions
    ),
    "dms_replication_subnet_groups": (
        collect_dms_replication_subnet_groups
    ),
    "dms_replication_tasks": (
        collect_dms_replication_tasks
    ),
    "dms_endpoints": collect_dms_endpoints,
}
