from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class RiskContext:
    """
    Context used to calculate the effective risk of a finding.
    """

    internet_exposed: bool = False
    sensitive_data: bool = False
    asset_criticality: int = 1
    exploitability: int = 1


@dataclass(frozen=True)
class RiskScore:
    """
    Calculated risk result for a finding.
    """

    score: float
    level: RiskLevel
    factors: dict[str, float]
