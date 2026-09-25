from dataclasses import dataclass


ENABLED = "ENABLED"


@dataclass(frozen=True)
class MacieControlResult:
    resource_id: str
    control_name: str
    expected_configuration: str
    actual_configuration: str


def check_enabled(
    resource_id: str,
    status: str | None,
    *,
    control_name: str,
) -> MacieControlResult | None:
    if status == ENABLED:
        return None

    return MacieControlResult(
        resource_id=resource_id,
        control_name=control_name,
        expected_configuration=ENABLED,
        actual_configuration=(
            status
            if status is not None
            else "MISSING"
        ),
    )
