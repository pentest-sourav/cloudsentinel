from typing import Any, Callable

from scanner.aws.collectors.dynamodb import DynamoDBDataCollector


def collect_dynamodb_tables(
    collector: DynamoDBDataCollector,
) -> list[dict]:
    return collector.collect_tables()


def collect_dynamodb_dax_clusters(
    collector: DynamoDBDataCollector,
) -> list[dict]:
    return collector.collect_dax_clusters()


DYNAMODB_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[DynamoDBDataCollector], Any],
] = {
    "dynamodb_tables": collect_dynamodb_tables,
    "dynamodb_dax_clusters": collect_dynamodb_dax_clusters,
}
