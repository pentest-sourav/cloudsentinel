from pydantic import BaseModel


class FindingLifecycleItem(BaseModel):
    fingerprint: str
    status: str
    provider: str
    rule_id: str
    resource_type: str
    resource_id: str
    current_finding_id: int | None
    first_seen_scan_id: int
    last_seen_scan_id: int


class FindingLifecycleResponse(BaseModel):
    scan_id: int
    previous_scan_id: int | None
    items: list[FindingLifecycleItem]
    new: int
    open: int
    reopened: int
    resolved: int
