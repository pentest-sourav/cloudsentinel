from scanner.aws.collectors.cloudformation import (
    CloudFormationDataCollector,
)


def collect_cloudformation_stacks(
    collector: CloudFormationDataCollector,
) -> list[dict]:
    return collector.collect_stacks()


CLOUDFORMATION_DATA_SOURCE_HANDLERS = {
    "cloudformation_stacks": collect_cloudformation_stacks,
}
