from unittest.mock import MagicMock

from engine.rules.registry.kms_handlers import collect_kms_keys


def test_collect_kms_keys_handler():
    collector = MagicMock()
    collector.collect_keys.return_value = [{"key_id": "key-1"}]

    assert collect_kms_keys(collector) == [
        {"key_id": "key-1"}
    ]
