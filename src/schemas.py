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