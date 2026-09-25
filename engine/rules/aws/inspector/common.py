from dataclasses import dataclass


ENABLED = "ENABLED"


@dataclass(frozen=True)
class InspectorControlResult:
    resource_id: str
    control_name: str
    status_field: str
    expected_status: str
    actual_status: str


def check_scanning_enabled(
    resource_id: str,
    status: str | None,
    *,
    control_name: str,
    status_field: str,
) -> InspectorControlResult | None:
    if status == ENABLED:
        return None

    return InspectorControlResult(
        resource_id=resource_id,
        control_name=control_name,
        status_field=status_field,
        expected_status=ENABLED,
        actual_status=(
            status
            if status is not None
            else "MISSING"
        ),
    )
