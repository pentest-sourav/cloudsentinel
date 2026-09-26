from scanner.aws.collectors.emr import EMRDataCollector


def collect_emr_clusters(
    collector: EMRDataCollector,
) -> list[dict]:
    return collector.collect_clusters()


def collect_emr_security_configurations(
    collector: EMRDataCollector,
) -> list[dict]:
    return collector.collect_security_configurations()


def collect_emr_block_public_access(
    collector: EMRDataCollector,
) -> list[dict]:
    return collector.collect_block_public_access()


EMR_DATA_SOURCE_HANDLERS = {
    "emr_clusters": collect_emr_clusters,
    "emr_security_configurations": (
        collect_emr_security_configurations
    ),
    "emr_block_public_access": (
        collect_emr_block_public_access
    ),
}
