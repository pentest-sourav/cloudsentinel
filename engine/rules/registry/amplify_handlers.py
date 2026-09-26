from scanner.aws.collectors.amplify import (
    AmplifyDataCollector,
)


def collect_amplify_apps(
    collector: AmplifyDataCollector,
) -> list[dict]:
    return collector.collect_apps()


def collect_amplify_branches(
    collector: AmplifyDataCollector,
) -> list[dict]:
    return collector.collect_branches()


AMPLIFY_DATA_SOURCE_HANDLERS = {
    "amplify_apps": collect_amplify_apps,
    "amplify_branches": collect_amplify_branches,
}
