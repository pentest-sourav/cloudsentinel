from scanner.aws.collectors.cloudfront import (
    CloudFrontDataCollector,
)


def collect_cloudfront_distributions(
    collector: CloudFrontDataCollector,
) -> list[dict]:
    return collector.collect_distributions()


CLOUDFRONT_DATA_SOURCE_HANDLERS = {
    "cloudfront_distributions": (
        collect_cloudfront_distributions
    ),
}
