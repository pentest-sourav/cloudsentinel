from scanner.aws.collectors.acm import ACMDataCollector


def collect_acm_certificates(
    collector: ACMDataCollector,
) -> list[dict]:
    return collector.collect_certificates()


ACM_DATA_SOURCE_HANDLERS = {
    "acm_certificates": collect_acm_certificates,
}
