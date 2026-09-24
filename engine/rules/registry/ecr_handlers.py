from scanner.aws.collectors.ecr import ECRDataCollector


def collect_ecr_repositories(
    collector: ECRDataCollector,
) -> list[dict]:
    return collector.collect_repositories()


ECR_DATA_SOURCE_HANDLERS = {
    "ecr_repositories": collect_ecr_repositories,
}
