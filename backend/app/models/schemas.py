from pydantic import BaseModel
from typing import List, Optional, Dict, Any

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
    score_breakdown: Optional[ScoreBreakdown] = None
    improvement_priority: Optional[List[ImprovementPriority]] = None


class AnalyzeWithPdfResponse(BaseModel):
    analysis: AnalyzeResponse
    pdf_url: str
    cid: str
    report_id: str
    contract_hash: str
    # NEW dynamic fields (all optional — absent when dynamic analysis not performed):
    contract_id: Optional[str] = None
    dynamic_audit_log: Optional[List['DynamicLogEntry']] = None
    anomalies_found: Optional[int] = None
    dynamic_risk_adjustment: Optional[int] = None
    dynamic_status: Optional[str] = None  # "OK" | failure codes


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


class GenerateReportRequest(BaseModel):
    analysis: AnalyzeResponse
    contract_name: Optional[str] = "Unknown Contract"


class GenerateReportResponse(BaseModel):
    cid: str
    pdf_url: str
    report_id: str
    download_url: str


class AnchorRequest(BaseModel):
    contract_hash: str
    report_hash: str
    risk_score: int
    ipfs_cid: str
    contract_name: Optional[str] = "Unknown Contract"
    # NEW:
    dynamic_anomalies_count: int = 0
    dynamic_risk_adjustment: int = 0


class AnchorResponse(BaseModel):
    tx_hash: str
    explorer_url: str
    contract_address: str
    timestamp: str
    source: str


class VerifyResponse(BaseModel):
    contract_hash: str
    report_hash: str
    risk_score: int
    ipfs_cid: str
    timestamp: str
    auditor: str
    source: str


class HistoryRecord(BaseModel):
    contract_hash: str
    report_hash: str
    risk_score: int
    ipfs_cid: Optional[str]
    auditor: str
    created_at: str
    source: str


class StatusResponse(BaseModel):
    api_status: str
    version: str
    endpoints: List[str]
    groq_connected: bool
    stellar_connected: bool
    pinata_connected: bool
    dynamic_analysis_enabled: bool


# Dynamic Analysis Schemas

class DynamicLogEntry(BaseModel):
    timestamp: str  # ISO-8601 UTC, e.g. "2025-04-30T14:23:11Z"
    transaction_hash: str  # Stellar transaction hash or "timeout_{n}"
    function_called: str  # exported function name
    parameters: Dict[str, Any]  # key-value pairs of parameter name → value
    result: Optional[str] = None  # return value string, None on error/timeout
    error: Optional[str] = None  # error message, None on success
    anomaly: bool  # True if Groq classified as anomaly
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
    status: str  # "NORMAL" | "SUSPICIOUS" | "FLAGGED"
    reason: str  # Groq explanation or "" for NORMAL


class DynamicAnalyzeRequest(BaseModel):
    contract_code: str
    contract_name: Optional[str] = "Unknown Contract"
    contract_hash: str  # hex SHA-256 of contract_code


class DynamicAnalyzeResponse(BaseModel):
    contract_id: Optional[str]  # Stellar C... address or None on deploy failure
    dynamic_audit_log: List[DynamicLogEntry]
    anomalies_found: int
    dynamic_risk_adjustment: int
    dynamic_status: str  # "OK" | "DEPLOY_FAILED" | "HORIZON_UNAVAILABLE" | "TIMEOUT"


class SentinelFeedEntry(BaseModel):
    timestamp: str  # ISO-8601 UTC
    event: str  # "NORMAL_TX" | "SUSPICIOUS_TX" | "FLAGGED_TX"
    function: str  # function name
    params: Dict[str, Any]  # parameter key-value pairs
    status: str  # "NORMAL" | "SUSPICIOUS" | "FLAGGED"
    reason: str  # explanation or ""


class AuditBounds(BaseModel):
    max_param_value: int  # maximum expected parameter value
    expected_functions: List[str]  # list of expected function names
    risk_score: int  # static risk score baseline


# Update forward references
AnalyzeWithPdfResponse.model_rebuild()
