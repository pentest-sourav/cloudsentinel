from scanner.aws.collectors.vpc import VPCDataCollector


def collect_vpcs(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_vpcs()


def collect_internet_gateways(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_internet_gateways()


VPC_DATA_SOURCE_HANDLERS = {
    "vpcs": collect_vpcs,
    "internet_gateways": collect_internet_gateways,
}
