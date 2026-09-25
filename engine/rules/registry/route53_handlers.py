from scanner.aws.collectors.route53 import (
    Route53DataCollector,
)


def collect_route53_health_checks(
    collector: Route53DataCollector,
) -> list[dict]:
    return collector.collect_health_checks()


def collect_route53_hosted_zones(
    collector: Route53DataCollector,
) -> list[dict]:
    return collector.collect_hosted_zones()


ROUTE53_DATA_SOURCE_HANDLERS = {
    "route53_health_checks": collect_route53_health_checks,
    "route53_hosted_zones": collect_route53_hosted_zones,
}
