"""
Unit tests for report router endpoints.

Tests error handling and edge cases for report generation and download.

**Validates: Requirements 2.4, 2.5, 2.7**
"""

from pathlib import Path
import sys
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


client = TestClient(app)


def test_report_download_not_found():
    """
    Test that GET /report/download/nonexistent returns 404.
    
    **Validates: Requirement 2.7**
    """
    response = client.get("/report/download/nonexistent")
    
    assert response.status_code == 404
    assert "detail" in response.json()
    assert "not found" in response.json()["detail"].lower()


def test_report_generate_missing_analysis():
    """
    Test that POST /report/generate with empty body returns 422.
    
    **Validates: Requirement 2.4**
    """
    # Send empty JSON body
    response = client.post(
        "/report/generate",
        json={}
    )
    
    assert response.status_code == 422
    # FastAPI returns validation error details
    assert "detail" in response.json()


def test_report_generate_invalid_analysis():
    """
    Test that POST /report/generate with invalid analysis data returns 422.
    
    **Validates: Requirement 2.4**
    """
    # Send invalid analysis (missing required fields)
    response = client.post(
        "/report/generate",
        json={
            "analysis": {
                "risk_score": "not_a_number",  # Should be int
                "vulnerabilities": "not_a_list",  # Should be list
            },
            "contract_name": "Test Contract"
        }
    )
    
    assert response.status_code == 422
    assert "detail" in response.json()


@patch('app.routers.report.upload_pdf_to_ipfs')
@patch('app.routers.report.generate_audit_report')
def test_pinata_failure(mock_generate_report, mock_upload_ipfs):
    """
    Test that when upload_pdf_to_ipfs raises RuntimeError, endpoint returns 502.
    
    **Validates: Requirement 2.5**
    """
    # Mock generate_audit_report to return a valid path and report_id
    mock_generate_report.return_value = ("/fake/path/report.pdf", "20260430_120000")
    
    # Mock upload_pdf_to_ipfs to raise RuntimeError
    mock_upload_ipfs.side_effect = RuntimeError("Pinata service unavailable")
    
    # Valid analysis data
    valid_analysis = {
        "risk_score": 75,
        "vulnerabilities": [
            {
                "title": "Test Vulnerability",
                "severity": "HIGH",
                "description": "Test description",
                "line": 42,
                "fix": "Test fix"
            }
        ],
        "exploit_story": "Test exploit story"
    }
    
    response = client.post(
        "/report/generate",
        json={
            "analysis": valid_analysis,
            "contract_name": "Test Contract"
        }
    )
    
    assert response.status_code == 502
    assert "detail" in response.json()
    assert "IPFS upload failed" in response.json()["detail"]


@patch('app.routers.report.upload_pdf_to_ipfs')
@patch('app.routers.report.generate_audit_report')
def test_report_generate_success(mock_generate_report, mock_upload_ipfs):
    """
    Test successful report generation flow.
    
    This is a positive test to ensure the mocking works correctly.
    """
    # Mock generate_audit_report
    mock_generate_report.return_value = ("/fake/path/report.pdf", "20260430_120000")
    
    # Mock upload_pdf_to_ipfs
    mock_upload_ipfs.return_value = {
        "cid": "QmTestCID123",
        "url": "https://gateway.pinata.cloud/ipfs/QmTestCID123"
    }
    
    valid_analysis = {
        "risk_score": 50,
        "vulnerabilities": [],
        "exploit_story": "No exploits found"
    }
    
    response = client.post(
        "/report/generate",
        json={
            "analysis": valid_analysis,
            "contract_name": "Safe Contract"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert "cid" in data
    assert "pdf_url" in data
    assert "report_id" in data
    assert "download_url" in data
    
    assert data["cid"] == "QmTestCID123"
    assert data["report_id"] == "20260430_120000"
    assert data["download_url"] == "/report/download/20260430_120000"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
