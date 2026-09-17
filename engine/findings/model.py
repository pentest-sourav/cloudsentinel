from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    provider: str
    resource_type: str
    resource_id: str
    description: str
    evidence: dict[str, object] = field(default_factory=dict)
    remediation: str = ""
    compliance: list[str] = field(default_factory=list)
