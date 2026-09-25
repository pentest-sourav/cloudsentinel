from dataclasses import dataclass


@dataclass(frozen=True)
class WAFResourceResult:
    resource_id: str
    resource_arn: str
    name: str
    scope: str
