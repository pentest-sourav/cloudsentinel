from scanner.aws.collectors.elb import ELBDataCollector


def collect_elb_load_balancers(
    collector: ELBDataCollector,
) -> list[dict]:
    return collector.collect_load_balancers()


ELB_DATA_SOURCE_HANDLERS = {
    "elb_load_balancers": collect_elb_load_balancers,
}
