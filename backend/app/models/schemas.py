from pydantic import BaseModel
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    contract_code: str
    contract_name: Optional[str] = "Unknown Contract"

class Vulnerability(BaseModel):
    id: str
    type: str
    severity: str
    line: Optional[int] = None
    title: str
    description: str
    impact: str
    fix: str
    score_contribution: int

class ScoreBreakdown(BaseModel):
    reasoning: str
    positives: List[str]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

class ImprovementPriority(BaseModel):
    order: int
    fix: str
    effort: str
    severity: str

class AnalyzeResponse(BaseModel):
    risk_score: int
    risk_level: str
    summary: str
    vulnerabilities: List[Vulnerability]
    score_breakdown: ScoreBreakdown
    improvement_priority: List[ImprovementPriority]
    exploit_story: str