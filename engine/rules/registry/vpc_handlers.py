from scanner.aws.collectors.vpc import VPCDataCollector


def collect_vpcs(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_vpcs()


def collect_internet_gateways(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_internet_gateways()


def collect_default_security_groups(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_default_security_groups()


def collect_flow_log_coverage(
    collector: VPCDataCollector,
) -> list[dict]:
    return collector.collect_flow_log_coverage()


VPC_DATA_SOURCE_HANDLERS = {
    "vpcs": collect_vpcs,
    "internet_gateways": collect_internet_gateways,
    "default_security_groups": collect_default_security_groups,
    "flow_log_coverage": collect_flow_log_coverage,
}
