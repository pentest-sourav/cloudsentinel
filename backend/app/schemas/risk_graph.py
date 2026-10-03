from pydantic import BaseModel


class RiskGraphAsset(BaseModel):
    resource_type: str
    resource_id: str
    region: str
    finding_count: int
    max_risk_score: float
    average_risk_score: float
    highest_risk_level: str
    internet_exposed: bool
    sensitive_data: bool
    asset_criticality: int
    exploitability: int


class RiskGraphRelationship(BaseModel):
    source: str
    target: str
    relationship: str
    evidence_derived: bool


class RiskGraphAttackPath(BaseModel):
    path_id: str
    title: str
    risk_level: str
    resource_type: str
    resource_id: str
    region: str
    confidence: str
    steps: list[str]
    rationale: str


class RiskGraphResponse(BaseModel):
    scan_id: int
    provider: str
    status: str
    graph_type: str
    evidence_derived: bool
    asset_count: int
    finding_count: int
    exposed_asset_count: int
    sensitive_asset_count: int
    assets: list[RiskGraphAsset]
    relationships: list[RiskGraphRelationship]
    attack_paths: list[RiskGraphAttackPath]
