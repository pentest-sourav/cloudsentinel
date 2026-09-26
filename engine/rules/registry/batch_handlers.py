from scanner.aws.collectors.batch import BatchDataCollector


def collect_batch_job_queues(
    collector: BatchDataCollector,
) -> list[dict]:
    return collector.collect_job_queues()


def collect_batch_scheduling_policies(
    collector: BatchDataCollector,
) -> list[dict]:
    return collector.collect_scheduling_policies()


def collect_batch_compute_environments(
    collector: BatchDataCollector,
) -> list[dict]:
    return collector.collect_compute_environments()


def collect_batch_compute_resource_tags(
    collector: BatchDataCollector,
) -> list[dict]:
    return collector.collect_managed_compute_resource_tags()


BATCH_DATA_SOURCE_HANDLERS = {
    "batch_job_queues": collect_batch_job_queues,
    "batch_scheduling_policies": (
        collect_batch_scheduling_policies
    ),
    "batch_compute_environments": (
        collect_batch_compute_environments
    ),
    "batch_compute_resource_tags": (
        collect_batch_compute_resource_tags
    ),
}
