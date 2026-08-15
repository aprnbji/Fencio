from pydantic import BaseModel, Field


class ReconItem(BaseModel):
    query: str
    response: str


class ReconResult(BaseModel):
    items: list[ReconItem] = Field(default_factory=list)


class Evidence(BaseModel):
    query: str
    response: str


class AttackSurface(BaseModel):
    surface: str
    evidence: Evidence
    vector: str
    risk: str


class VulnerabilityReport(BaseModel):
    summary: str
    attack_surfaces: list[AttackSurface] = Field(default_factory=list)


class JudgeVerdict(BaseModel):
    score: int
    confirmed: bool
    evidence: str
    feedback: str


class AttackFinding(BaseModel):
    session_id: str
    vulnerability: str
    severity: str
    description: str
    evidence: Evidence
    impact: str
    remediation: str
    best_score: int