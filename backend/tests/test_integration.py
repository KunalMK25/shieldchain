"""
Integration tests for full scan and report flow.

These tests verify end-to-end functionality with real external services.
They are marked with @pytest.mark.integration and skip in CI unless GROQ_API_KEY is set.

**Validates: Requirements 2.1, 7.3**
"""

from pathlib import Path
import sys
import os

import pytest
from fastapi.testclient import TestClient

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


client = TestClient(app)


# Minimal Rust contract for testing
MINIMAL_RUST_CONTRACT = """
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct HelloContract;

#[contractimpl]
impl HelloContract {
    pub fn hello(env: Env, to: Symbol) -> Symbol {
        to
    }
}
"""


@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API_KEY") == "",
    reason="GROQ_API_KEY not set - skipping integration test"
)
def test_full_scan_flow():
    """
    Test the full scan flow with a real Groq API key and minimal Rust contract.
    
    POST /analyze/ with a real Groq API key and a minimal Rust contract;
    assert the response matches AnalyzeWithPdfResponse shape and risk_score is in [0, 100].
    
    **Validates: Requirement 7.3**
    """
    # POST to /analyze/ with minimal Rust contract
    response = client.post(
        "/analyze/",
        json={
            "contract_code": MINIMAL_RUST_CONTRACT,
            "contract_name": "HelloContract"
        }
    )
    
    # Assert successful response
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    
    data = response.json()
    
    # Verify AnalyzeWithPdfResponse shape
    assert "analysis" in data, "Response missing 'analysis' field"
    assert "pdf_url" in data, "Response missing 'pdf_url' field"
    assert "cid" in data, "Response missing 'cid' field"
    assert "report_id" in data, "Response missing 'report_id' field"
    assert "contract_hash" in data, "Response missing 'contract_hash' field"
    
    # Verify analysis structure
    analysis = data["analysis"]
    assert "risk_score" in analysis, "Analysis missing 'risk_score' field"
    assert "vulnerabilities" in analysis, "Analysis missing 'vulnerabilities' field"
    assert "exploit_story" in analysis, "Analysis missing 'exploit_story' field"
    
    # Verify risk_score is in valid range [0, 100]
    risk_score = analysis["risk_score"]
    assert isinstance(risk_score, int), f"risk_score should be int, got {type(risk_score)}"
    assert 0 <= risk_score <= 100, f"risk_score {risk_score} not in range [0, 100]"
    
    # Verify vulnerabilities is a list
    assert isinstance(analysis["vulnerabilities"], list), "vulnerabilities should be a list"
    
    # Verify each vulnerability has required fields
    for vuln in analysis["vulnerabilities"]:
        assert "title" in vuln, "Vulnerability missing 'title' field"
        assert "severity" in vuln, "Vulnerability missing 'severity' field"
        assert "description" in vuln, "Vulnerability missing 'description' field"
        assert "line" in vuln, "Vulnerability missing 'line' field"
        assert "fix" in vuln, "Vulnerability missing 'fix' field"
        
        # Verify severity is valid
        assert vuln["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"], \
            f"Invalid severity: {vuln['severity']}"
    
    # Verify exploit_story is a string
    assert isinstance(analysis["exploit_story"], str), "exploit_story should be a string"
    
    # Verify pdf_url is a valid URL string
    assert isinstance(data["pdf_url"], str), "pdf_url should be a string"
    assert data["pdf_url"].startswith("http"), f"pdf_url should be a URL: {data['pdf_url']}"
    
    # Verify cid is a non-empty string
    assert isinstance(data["cid"], str), "cid should be a string"
    assert len(data["cid"]) > 0, "cid should be non-empty"
    
    # Verify report_id is a non-empty string
    assert isinstance(data["report_id"], str), "report_id should be a string"
    assert len(data["report_id"]) > 0, "report_id should be non-empty"
    
    # Verify contract_hash is a 64-character hex string (SHA-256)
    assert isinstance(data["contract_hash"], str), "contract_hash should be a string"
    assert len(data["contract_hash"]) == 64, \
        f"contract_hash should be 64 chars (SHA-256 hex), got {len(data['contract_hash'])}"
    assert all(c in "0123456789abcdef" for c in data["contract_hash"]), \
        "contract_hash should be lowercase hex"


@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API_KEY") == "" or 
    not os.getenv("PINATA_API_KEY") or os.getenv("PINATA_API_KEY") == "",
    reason="GROQ_API_KEY or PINATA_API_KEY not set - skipping integration test"
)
def test_full_report_flow():
    """
    Test the full report generation flow with a valid analysis.
    
    POST /report/generate with a valid analysis; assert the PDF file exists
    in backend/reports/ and the download_url resolves to 200.
    
    **Validates: Requirement 2.1**
    """
    # Valid analysis data
    valid_analysis = {
        "risk_score": 42,
        "vulnerabilities": [
            {
                "title": "Test Vulnerability",
                "severity": "MEDIUM",
                "description": "This is a test vulnerability for integration testing.",
                "line": 10,
                "fix": "Apply the recommended fix."
            }
        ],
        "exploit_story": "An attacker could potentially exploit this vulnerability by...",
        "score_breakdown": {
            "reasoning": "The contract has one medium severity issue.",
            "positives": ["Good code structure", "Proper error handling"],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0
        },
        "improvement_priority": [
            {
                "order": 1,
                "fix": "Fix the test vulnerability",
                "effort": "Low",
                "severity": "MEDIUM"
            }
        ]
    }
    
    # POST to /report/generate
    response = client.post(
        "/report/generate",
        json={
            "analysis": valid_analysis,
            "contract_name": "IntegrationTestContract"
        }
    )
    
    # Assert successful response
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    
    data = response.json()
    
    # Verify GenerateReportResponse shape
    assert "cid" in data, "Response missing 'cid' field"
    assert "pdf_url" in data, "Response missing 'pdf_url' field"
    assert "report_id" in data, "Response missing 'report_id' field"
    assert "download_url" in data, "Response missing 'download_url' field"
    
    # Verify fields are non-empty strings
    assert isinstance(data["cid"], str) and len(data["cid"]) > 0, "cid should be non-empty string"
    assert isinstance(data["pdf_url"], str) and len(data["pdf_url"]) > 0, \
        "pdf_url should be non-empty string"
    assert isinstance(data["report_id"], str) and len(data["report_id"]) > 0, \
        "report_id should be non-empty string"
    assert isinstance(data["download_url"], str) and len(data["download_url"]) > 0, \
        "download_url should be non-empty string"
    
    # Verify download_url format
    expected_download_url = f"/report/download/{data['report_id']}"
    assert data["download_url"] == expected_download_url, \
        f"download_url should be {expected_download_url}, got {data['download_url']}"
    
    # Verify PDF file exists in backend/reports/
    backend_dir = Path(__file__).resolve().parents[1]
    reports_dir = backend_dir / "reports"
    pdf_filename = f"shieldchain_audit_{data['report_id']}.pdf"
    pdf_path = reports_dir / pdf_filename
    
    assert pdf_path.exists(), f"PDF file not found at {pdf_path}"
    assert pdf_path.is_file(), f"PDF path exists but is not a file: {pdf_path}"
    
    # Verify PDF file is non-empty
    pdf_size = pdf_path.stat().st_size
    assert pdf_size > 0, f"PDF file is empty: {pdf_path}"
    
    # Verify PDF file starts with PDF magic bytes
    with open(pdf_path, "rb") as f:
        magic_bytes = f.read(4)
        assert magic_bytes == b"%PDF", \
            f"PDF file does not start with %PDF magic bytes: {magic_bytes}"
    
    # Verify download_url resolves to 200
    download_response = client.get(data["download_url"])
    assert download_response.status_code == 200, \
        f"Download URL returned {download_response.status_code}, expected 200"
    
    # Verify Content-Type is application/pdf
    assert download_response.headers.get("content-type") == "application/pdf", \
        f"Expected Content-Type: application/pdf, got {download_response.headers.get('content-type')}"
    
    # Verify response body is non-empty
    assert len(download_response.content) > 0, "Download response body is empty"
    
    # Verify response body starts with PDF magic bytes
    assert download_response.content[:4] == b"%PDF", \
        "Download response does not start with %PDF magic bytes"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
