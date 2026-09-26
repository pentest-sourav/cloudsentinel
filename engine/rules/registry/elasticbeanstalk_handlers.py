from scanner.aws.collectors.elasticbeanstalk import (
    ElasticBeanstalkDataCollector,
)


def collect_elasticbeanstalk_environments(
    collector: ElasticBeanstalkDataCollector,
) -> list[dict]:
    return collector.collect_environments()


ELASTICBEANSTALK_DATA_SOURCE_HANDLERS = {
    "elasticbeanstalk_environments": (
        collect_elasticbeanstalk_environments
    ),
}
