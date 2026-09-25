from typing import Any, Callable

from scanner.aws.collectors.ecs import ECSDataCollector


def collect_ecs_clusters(
    collector: ECSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_clusters()


def collect_ecs_services(
    collector: ECSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_services()


def collect_ecs_task_definitions(
    collector: ECSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_task_definitions()


def collect_ecs_task_sets(
    collector: ECSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_task_sets()


def collect_ecs_capacity_providers(
    collector: ECSDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_capacity_providers()


ECS_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[ECSDataCollector], Any],
] = {
    "ecs_clusters": collect_ecs_clusters,
    "ecs_services": collect_ecs_services,
    "ecs_task_definitions": collect_ecs_task_definitions,
    "ecs_task_sets": collect_ecs_task_sets,
    "ecs_capacity_providers": collect_ecs_capacity_providers,
}
