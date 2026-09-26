from scanner.aws.collectors.appconfig import (
    AppConfigDataCollector,
)


def collect_appconfig_applications(
    collector: AppConfigDataCollector,
) -> list[dict]:
    return collector.collect_applications()


def collect_appconfig_configuration_profiles(
    collector: AppConfigDataCollector,
) -> list[dict]:
    return collector.collect_configuration_profiles()


def collect_appconfig_environments(
    collector: AppConfigDataCollector,
) -> list[dict]:
    return collector.collect_environments()


def collect_appconfig_extension_associations(
    collector: AppConfigDataCollector,
) -> list[dict]:
    return collector.collect_extension_associations()


APPCONFIG_DATA_SOURCE_HANDLERS = {
    "appconfig_applications": (
        collect_appconfig_applications
    ),
    "appconfig_configuration_profiles": (
        collect_appconfig_configuration_profiles
    ),
    "appconfig_environments": (
        collect_appconfig_environments
    ),
    "appconfig_extension_associations": (
        collect_appconfig_extension_associations
    ),
}
