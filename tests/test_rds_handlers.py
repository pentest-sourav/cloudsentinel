from unittest.mock import MagicMock

from engine.rules.registry.rds_handlers import (
    RDS_DATA_SOURCE_HANDLERS,
    collect_rds_instances,
)


def test_collect_rds_instances_calls_collector():
    collector = MagicMock()

    collector.collect_instances.return_value = [
        {
            "db_instance_id": "cloudsentinel-db",
            "publicly_accessible": True,
        }
    ]

    result = collect_rds_instances(collector)

    assert result == [
        {
            "db_instance_id": "cloudsentinel-db",
            "publicly_accessible": True,
        }
    ]

    collector.collect_instances.assert_called_once()


def test_rds_data_source_handler_is_registered():
    assert "rds_instances" in RDS_DATA_SOURCE_HANDLERS
    assert RDS_DATA_SOURCE_HANDLERS["rds_instances"] is collect_rds_instances
