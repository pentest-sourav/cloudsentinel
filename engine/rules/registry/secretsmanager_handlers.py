from typing import Any, Callable

from scanner.aws.collectors.secretsmanager import (
    SecretsManagerDataCollector,
)


def collect_secretsmanager_secrets(
    collector: SecretsManagerDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_secrets()


SECRETSMANAGER_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[
        [SecretsManagerDataCollector],
        Any,
    ],
] = {
    "secretsmanager_secrets": (
        collect_secretsmanager_secrets
    ),
}
