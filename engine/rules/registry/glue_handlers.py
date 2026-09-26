from scanner.aws.collectors.glue import GlueDataCollector


def collect_glue_jobs(
    collector: GlueDataCollector,
) -> list[dict]:
    return collector.collect_jobs()


def collect_glue_ml_transforms(
    collector: GlueDataCollector,
) -> list[dict]:
    return collector.collect_ml_transforms()


GLUE_DATA_SOURCE_HANDLERS = {
    "glue_jobs": collect_glue_jobs,
    "glue_ml_transforms": collect_glue_ml_transforms,
}
