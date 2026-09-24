from unittest.mock import MagicMock

from engine.rules.registry.ecr_handlers import (
    collect_ecr_repositories,
)


def test_collect_ecr_repositories_delegates_to_collector():
    collector = MagicMock()
    collector.collect_repositories.return_value = [
        {"repository_name": "test"}
    ]

    result = collect_ecr_repositories(collector)

    assert result == [{"repository_name": "test"}]
    collector.collect_repositories.assert_called_once()
