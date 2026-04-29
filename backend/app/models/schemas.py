from pydantic import BaseModel
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    contract_code: str
    contract_name: Optional[str] = "Unknown Contract"

class Vulnerability(BaseModel):
    title: str
    severity: str
    description: str
    line: int
    fix: str

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
    vulnerabilities: List[Vulnerability]
    exploit_story: str


class AnalyzeWithPdfResponse(BaseModel):
    analysis: AnalyzeResponse
    pdf_url: str
    cid: str


class RegisterAuditRequest(BaseModel):
    contract_code: str
    analysis: AnalyzeResponse
    report_text: str
    ipfs_cid: Optional[str] = None
    auditor: str = "local-dev"


class AuditRecordResponse(BaseModel):
    audit_id: str
    contract_hash: str
    report_hash: str
    risk_score: int
    risk_level: str
    ipfs_cid: Optional[str] = None
    auditor: str
    created_at: str
    source: str