from typing import Any


ENABLED = "ENABLED"


def feature_enabled(
    features: dict[str, dict[str, Any]] | None,
    feature_name: str,
) -> bool:
    if not isinstance(features, dict):
        return False

    feature = features.get(feature_name)

    if not isinstance(feature, dict):
        return False

    return feature.get("Status") == ENABLED


def additional_configuration_enabled(
    features: dict[str, dict[str, Any]] | None,
    feature_name: str,
    configuration_name: str,
) -> bool:
    if not isinstance(features, dict):
        return False

    feature = features.get(feature_name)

    if not isinstance(feature, dict):
        return False

    configurations = feature.get(
        "AdditionalConfiguration",
        [],
    )

    if not isinstance(configurations, list):
        return False

    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue

        if (
            configuration.get("Name")
            == configuration_name
            and configuration.get("Status")
            == ENABLED
        ):
            return True

    return False
