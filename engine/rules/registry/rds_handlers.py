from scanner.aws.collectors.rds import RDSDataCollector


def collect_rds_instances(
    collector: RDSDataCollector,
) -> list[dict]:
    """
    Collect normalized RDS DB instance data
    for the rule executor.
    """
    return collector.collect_instances()


RDS_DATA_SOURCE_HANDLERS = {
    "rds_instances": collect_rds_instances,
}
