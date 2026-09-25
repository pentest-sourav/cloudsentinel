from scanner.aws.collectors.guardduty import (
    GuardDutyDataCollector,
)


def collect_guardduty_detectors(
    collector: GuardDutyDataCollector,
) -> list[dict]:
    return collector.collect_detectors()


GUARDDUTY_DATA_SOURCE_HANDLERS = {
    "guardduty_detectors": collect_guardduty_detectors,
}
