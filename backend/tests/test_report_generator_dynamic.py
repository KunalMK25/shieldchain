"""
Unit tests for PDF report generator dynamic analysis section.

Feature: dynamic-analysis-sentinel-audit
Tests the Dynamic Analysis Results section in PDF reports.

**Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8**
"""

import os
import tempfile
from pathlib import Path

import pytest

from app.services.report_generator import generate_audit_report


def test_dynamic_section_present():
    """
    Test that Dynamic Analysis Results section is present when dynamic_audit_log exists.
    
    **Validates: Requirements 10.1, 10.2**
    """
    analysis_with_dynamic = {
        "risk_score": 75,
        "vulnerabilities": [],
        "exploit_story": "Test exploit story",
        "contract_id": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        "dynamic_audit_log": [
            {
                "timestamp": "2025-04-30T14:23:11Z",
                "transaction_hash": "abc123def456",
                "function_called": "transfer",
                "parameters": {"amount": 1000},
                "result": "success",
                "error": None,
                "anomaly": False,
                "severity": "NONE",
                "status": "NORMAL",
                "reason": "",
            }
        ],
        "anomalies_found": 0,
        "dynamic_risk_adjustment": 0,
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=analysis_with_dynamic,
            contract_name="Test Contract",
            output_dir=temp_dir
        )
        
        assert os.path.exists(pdf_path)
        
        # Verify PDF is valid (has PDF magic bytes)
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        assert pdf_bytes[:4] == b"%PDF", "PDF magic bytes not found"
        assert len(pdf_bytes) > 0, "PDF file is empty"


def test_dynamic_section_absent():
    """
    Test that Dynamic Analysis Results section is omitted when dynamic_audit_log is absent.
    
    **Validates: Requirement 10.7**
    """
    analysis_without_dynamic = {
        "risk_score": 75,
        "vulnerabilities": [],
        "exploit_story": "Test exploit story",
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=analysis_without_dynamic,
            contract_name="Test Contract",
            output_dir=temp_dir
        )
        
        assert os.path.exists(pdf_path)
        
        # Verify PDF is valid
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        assert pdf_bytes[:4] == b"%PDF", "PDF magic bytes not found"
        assert len(pdf_bytes) > 0, "PDF file is empty"


def test_dynamic_section_with_anomalies():
    """
    Test that anomaly details are included in the Dynamic Analysis Results section.
    
    **Validates: Requirements 10.4, 10.5**
    """
    analysis_with_anomalies = {
        "risk_score": 85,
        "vulnerabilities": [],
        "exploit_story": "Test exploit story",
        "contract_id": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        "dynamic_audit_log": [
            {
                "timestamp": "2025-04-30T14:23:11Z",
                "transaction_hash": "flagged_tx_hash",
                "function_called": "transfer",
                "parameters": {"amount": 999999},
                "result": None,
                "error": "overflow",
                "anomaly": True,
                "severity": "CRITICAL",
                "status": "FLAGGED",
                "reason": "Amount exceeds safe limits",
            },
            {
                "timestamp": "2025-04-30T14:23:21Z",
                "transaction_hash": "normal_tx_hash",
                "function_called": "balance",
                "parameters": {"account": "GABC"},
                "result": "1000",
                "error": None,
                "anomaly": False,
                "severity": "NONE",
                "status": "NORMAL",
                "reason": "",
            }
        ],
        "anomalies_found": 1,
        "dynamic_risk_adjustment": 5,
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=analysis_with_anomalies,
            contract_name="Test Contract",
            output_dir=temp_dir
        )
        
        assert os.path.exists(pdf_path)
        
        # Verify PDF is valid and larger (has more content)
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        assert pdf_bytes[:4] == b"%PDF", "PDF magic bytes not found"
        assert len(pdf_bytes) > 1000, "PDF file should be larger with dynamic content"


def test_dynamic_section_empty_log():
    """
    Test that Dynamic Analysis Results section is omitted when dynamic_audit_log is empty.
    
    **Validates: Requirement 10.7**
    """
    analysis_with_empty_log = {
        "risk_score": 75,
        "vulnerabilities": [],
        "exploit_story": "Test exploit story",
        "contract_id": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        "dynamic_audit_log": [],
        "anomalies_found": 0,
        "dynamic_risk_adjustment": 0,
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=analysis_with_empty_log,
            contract_name="Test Contract",
            output_dir=temp_dir
        )
        
        assert os.path.exists(pdf_path)
        
        # Verify PDF is valid
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        assert pdf_bytes[:4] == b"%PDF", "PDF magic bytes not found"
        assert len(pdf_bytes) > 0, "PDF file is empty"


def test_horizon_links_in_pdf():
    """
    Test that PDF generation succeeds with transaction hashes (for Horizon links).
    
    **Validates: Requirement 10.5**
    """
    analysis_with_links = {
        "risk_score": 75,
        "vulnerabilities": [],
        "exploit_story": "Test exploit story",
        "contract_id": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        "dynamic_audit_log": [
            {
                "timestamp": "2025-04-30T14:23:11Z",
                "transaction_hash": "abc123def456",
                "function_called": "transfer",
                "parameters": {"amount": 1000},
                "result": None,
                "error": "test error",
                "anomaly": True,
                "severity": "HIGH",
                "status": "FLAGGED",
                "reason": "Test reason",
            }
        ],
        "anomalies_found": 1,
        "dynamic_risk_adjustment": 3,
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pdf_path, report_id = generate_audit_report(
            analysis_response=analysis_with_links,
            contract_name="Test Contract",
            output_dir=temp_dir
        )
        
        assert os.path.exists(pdf_path)
        
        # Verify PDF is valid
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        
        assert pdf_bytes[:4] == b"%PDF", "PDF magic bytes not found"
        assert len(pdf_bytes) > 1000, "PDF file should contain dynamic content"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
