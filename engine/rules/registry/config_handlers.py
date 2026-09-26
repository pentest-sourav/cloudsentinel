from scanner.aws.collectors.config import ConfigDataCollector


def collect_config_account(
    collector: ConfigDataCollector,
) -> dict:
    return collector.collect_account()


def collect_config_recorders(
    collector: ConfigDataCollector,
) -> list[dict]:
    return collector.collect_recorders()


CONFIG_DATA_SOURCE_HANDLERS = {
    "config_account": collect_config_account,
    "config_recorders": collect_config_recorders,
}
