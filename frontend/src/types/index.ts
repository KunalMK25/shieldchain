// frontend/src/types/index.ts

export interface Vulnerability {
  title:       string;
  severity:    'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  line:        number;
  fix:         string;
}

export interface ScoreBreakdown {
  reasoning:      string;
  positives:      string[];
  critical_count: number;
  high_count:     number;
  medium_count:   number;
  low_count:      number;
}

export interface ImprovementPriority {
  order:        number;
  fix:          string;
  effort:       string;
  severity:     string;
  before_code?: string;
  after_code?:  string;
  explanation?: string;
}

export interface AnalysisResult {
  risk_score:           number;
  vulnerabilities:      Vulnerability[];
  exploit_story:        string;
  score_breakdown?:     ScoreBreakdown;
  improvement_priority?: ImprovementPriority[];
}

export interface ScanResponse {
  analysis:                AnalysisResult;
  pdf_url:                 string;
  cid:                     string;
  report_id:               string;
  contract_hash:           string;
  // Dynamic fields (optional):
  contract_id?:            string;
  dynamic_audit_log?:      DynamicLogEntry[];
  anomalies_found?:        number;
  dynamic_risk_adjustment?: number;
  dynamic_status?:         string;
}

export interface AnchorResponse {
  tx_hash:          string;
  explorer_url:     string;
  contract_address: string;
  timestamp:        string;
  source:           string;
}

export interface AuditRecord {
  contract_hash: string;
  report_hash:   string;
  risk_score:    number;
  ipfs_cid:      string;
  timestamp?:    string;      // Used by VerifyResponse
  created_at?:   string;      // Used by HistoryRecord
  auditor:       string;
  source:        string;
}

export interface DynamicLogEntry {
  timestamp:        string;
  transaction_hash: string;
  function_called:  string;
  parameters:       Record<string, unknown>;
  result?:          string;
  error?:           string;
  anomaly:          boolean;
  severity:         'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  status:           'NORMAL' | 'SUSPICIOUS' | 'FLAGGED';
  reason:           string;
}

export interface SentinelFeedEntry {
  timestamp: string;
  event:     'NORMAL_TX' | 'SUSPICIOUS_TX' | 'FLAGGED_TX';
  function:  string;
  params:    Record<string, unknown>;
  status:    'NORMAL' | 'SUSPICIOUS' | 'FLAGGED';
  reason:    string;
}
