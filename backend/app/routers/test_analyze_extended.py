"""
Unit tests for the extended analyze router with dynamic analysis integration.

Tests:
- test_dynamic_failure_returns_200: mock dynamic analyzer to raise, verify HTTP 200 with dynamic_status
- test_dynamic_results_merged: mock successful dynamic analysis, verify merged response fields
- test_dynamic_timeout_returns_200: mock 91-second dynamic analysis, verify dynamic_status="TIMEOUT"

Validates: Requirements 5.3, 5.4, 13.4
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.models.schemas import (
    AnalyzeResponse,
    DynamicAnalyzeResponse,
    DynamicLogEntry,
    Vulnerability,
)
import asyncio


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def sample_contract_code():
    """Sample Soroban contract code for testing."""
    return """
    #![no_std]
    use soroban_sdk::{contract, contractimpl, Env, Symbol};
    
    #[contract]
    pub struct HelloContract;
    
    #[contractimpl]
    impl HelloContract {
        pub fn hello(env: Env, to: Symbol) -> Symbol {
            Symbol::new(&env, &"Hello")
        }
    }
    """


@pytest.fixture
def sample_static_analysis():
    """Sample static analysis response."""
    return AnalyzeResponse(
        risk_score=45,
        vulnerabilities=[
            Vulnerability(
                title="Unchecked Authorization",
                severity="HIGH",
                description="Function does not verify caller authorization",
                line=10,
                fix="Add authorization check using env.require_auth()"
            )
        ],
        exploit_story="An attacker could call the hello function without proper authorization.",
        score_breakdown=None,
        improvement_priority=None
    )


@pytest.fixture
def sample_dynamic_success():
    """Sample successful dynamic analysis response."""
    return DynamicAnalyzeResponse(
        contract_id="CTEST123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        dynamic_audit_log=[
            DynamicLogEntry(
                timestamp="2025-04-30T14:23:11Z",
                transaction_hash="tx_hash_001",
                function_called="hello",
                parameters={"to": "World"},
                result="Hello",
                error=None,
                anomaly=False,
                severity="NONE",
                status="NORMAL",
                reason=""
            ),
            DynamicLogEntry(
                timestamp="2025-04-30T14:23:21Z",
                transaction_hash="tx_hash_002",
                function_called="hello",
                parameters={"to": ""},
                result=None,
                error="Invalid parameter",
                anomaly=True,
                severity="MEDIUM",
                status="SUSPICIOUS",
                reason="Empty parameter detected"
            )
        ],
        anomalies_found=1,
        dynamic_risk_adjustment=2,
        dynamic_status="OK"
    )


@pytest.fixture
def sample_dynamic_failure():
    """Sample failed dynamic analysis response."""
    return DynamicAnalyzeResponse(
        contract_id=None,
        dynamic_audit_log=[],
        anomalies_found=0,
        dynamic_risk_adjustment=0,
        dynamic_status="DEPLOY_FAILED"
    )


def test_dynamic_failure_returns_200(
    client,
    sample_contract_code,
    sample_static_analysis,
    sample_dynamic_failure
):
    """
    Test that when dynamic analyzer raises an exception,
    the endpoint returns HTTP 200 with dynamic_status indicating failure.
    
    Validates: Requirements 5.3, 5.4, 13.4
    """
    # Mock the static analyzer to return successful analysis
    with patch("app.routers.analyze.analyze_contract") as mock_static:
        mock_static.return_value = sample_static_analysis
        
        # Mock the dynamic analyzer to raise an exception
        with patch("app.routers.analyze.run_dynamic_analysis") as mock_dynamic:
            mock_dynamic.side_effect = Exception("Deployment failed")
            
            # Mock PDF generation and IPFS upload
            with patch("app.routers.analyze.generate_audit_report") as mock_pdf:
                mock_pdf.return_value = ("/tmp/report.pdf", "report_123")
                
                with patch("app.routers.analyze.upload_pdf_to_ipfs") as mock_ipfs:
                    mock_ipfs.return_value = {
                        "url": "https://ipfs.io/ipfs/QmTest",
                        "cid": "QmTest"
                    }
                    
                    with patch("app.routers.analyze.generate_contract_and_pdf_hashes") as mock_hash:
                        mock_hash.return_value = {
                            "contract_hash": "abc123",
                            "pdf_hash": "def456"
                        }
                        
                        # Make the request
                        response = client.post(
                            "/analyze/",
                            json={
                                "contract_code": sample_contract_code,
                                "contract_name": "TestContract"
                            }
                        )
                        
                        # Should return HTTP 200 (not 500)
                        assert response.status_code == 200
                        
                        # Parse response
                        data = response.json()
                        
                        # Verify static analysis is present
                        assert "analysis" in data
                        assert data["analysis"]["risk_score"] == 45
                        
                        # Verify dynamic_status indicates failure
                        assert "dynamic_status" in data
                        assert data["dynamic_status"] == "DEPLOY_FAILED"
                        
                        # Verify dynamic fields are None or empty
                        assert data["contract_id"] is None
                        assert data["dynamic_audit_log"] is None
                        assert data["anomalies_found"] is None
                        assert data["dynamic_risk_adjustment"] is None
                        
                        # Verify PDF and IPFS fields are still present
                        assert "pdf_url" in data
                        assert "cid" in data
                        assert "report_id" in data


def test_dynamic_results_merged(
    client,
    sample_contract_code,
    sample_static_analysis,
    sample_dynamic_success
):
    """
    Test that successful dynamic analysis results are properly merged
    into the response alongside static analysis results.
    
    Validates: Requirements 5.2, 5.3
    """
    # Mock the static analyzer
    with patch("app.routers.analyze.analyze_contract") as mock_static:
        mock_static.return_value = sample_static_analysis
        
        # Mock the dynamic analyzer to return successful results
        with patch("app.routers.analyze.run_dynamic_analysis") as mock_dynamic:
            mock_dynamic.return_value = sample_dynamic_success
            
            # Mock PDF generation and IPFS upload
            with patch("app.routers.analyze.generate_audit_report") as mock_pdf:
                mock_pdf.return_value = ("/tmp/report.pdf", "report_123")
                
                with patch("app.routers.analyze.upload_pdf_to_ipfs") as mock_ipfs:
                    mock_ipfs.return_value = {
                        "url": "https://ipfs.io/ipfs/QmTest",
                        "cid": "QmTest"
                    }
                    
                    with patch("app.routers.analyze.generate_contract_and_pdf_hashes") as mock_hash:
                        mock_hash.return_value = {
                            "contract_hash": "abc123",
                            "pdf_hash": "def456"
                        }
                        
                        # Make the request
                        response = client.post(
                            "/analyze/",
                            json={
                                "contract_code": sample_contract_code,
                                "contract_name": "TestContract"
                            }
                        )
                        
                        # Should return HTTP 200
                        assert response.status_code == 200
                        
                        # Parse response
                        data = response.json()
                        
                        # Verify static analysis is present
                        assert "analysis" in data
                        assert data["analysis"]["risk_score"] == 45
                        
                        # Verify dynamic fields are merged
                        assert data["contract_id"] == "CTEST123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        assert data["dynamic_status"] == "OK"
                        assert data["anomalies_found"] == 1
                        assert data["dynamic_risk_adjustment"] == 2
                        
                        # Verify dynamic_audit_log is present and has correct entries
                        assert "dynamic_audit_log" in data
                        assert len(data["dynamic_audit_log"]) == 2
                        
                        # Verify first log entry (NORMAL)
                        entry1 = data["dynamic_audit_log"][0]
                        assert entry1["function_called"] == "hello"
                        assert entry1["status"] == "NORMAL"
                        assert entry1["anomaly"] is False
                        
                        # Verify second log entry (SUSPICIOUS)
                        entry2 = data["dynamic_audit_log"][1]
                        assert entry2["function_called"] == "hello"
                        assert entry2["status"] == "SUSPICIOUS"
                        assert entry2["anomaly"] is True
                        assert entry2["severity"] == "MEDIUM"
                        assert entry2["reason"] == "Empty parameter detected"
                        
                        # Verify PDF and IPFS fields are present
                        assert "pdf_url" in data
                        assert "cid" in data
                        assert "report_id" in data


def test_dynamic_timeout_returns_200(
    client,
    sample_contract_code,
    sample_static_analysis
):
    """
    Test that when dynamic analysis times out after 90 seconds,
    the endpoint returns HTTP 200 with dynamic_status="TIMEOUT".
    
    Validates: Requirements 5.4, 13.4, 13.5
    """
    # Mock the static analyzer
    with patch("app.routers.analyze.analyze_contract") as mock_static:
        mock_static.return_value = sample_static_analysis
        
        # Mock the dynamic analyzer to simulate a timeout
        # We'll use a coroutine that sleeps longer than the timeout
        async def slow_dynamic_analysis(*args, **kwargs):
            await asyncio.sleep(100)  # Sleep longer than 90s timeout
            return DynamicAnalyzeResponse(
                contract_id="SHOULD_NOT_REACH",
                dynamic_audit_log=[],
                anomalies_found=0,
                dynamic_risk_adjustment=0,
                dynamic_status="OK"
            )
        
        with patch("app.routers.analyze.run_dynamic_analysis") as mock_dynamic:
            mock_dynamic.side_effect = slow_dynamic_analysis
            
            # Mock PDF generation and IPFS upload
            with patch("app.routers.analyze.generate_audit_report") as mock_pdf:
                mock_pdf.return_value = ("/tmp/report.pdf", "report_123")
                
                with patch("app.routers.analyze.upload_pdf_to_ipfs") as mock_ipfs:
                    mock_ipfs.return_value = {
                        "url": "https://ipfs.io/ipfs/QmTest",
                        "cid": "QmTest"
                    }
                    
                    with patch("app.routers.analyze.generate_contract_and_pdf_hashes") as mock_hash:
                        mock_hash.return_value = {
                            "contract_hash": "abc123",
                            "pdf_hash": "def456"
                        }
                        
                        # Mock asyncio.wait_for to immediately raise TimeoutError
                        # This simulates the 90-second timeout without actually waiting
                        original_wait_for = asyncio.wait_for
                        
                        async def mock_wait_for(coro, timeout):
                            # Cancel the coroutine immediately
                            if hasattr(coro, 'close'):
                                coro.close()
                            raise asyncio.TimeoutError()
                        
                        with patch("asyncio.wait_for", side_effect=mock_wait_for):
                            # Make the request
                            response = client.post(
                                "/analyze/",
                                json={
                                    "contract_code": sample_contract_code,
                                    "contract_name": "TestContract"
                                }
                            )
                            
                            # Should return HTTP 200 (not 500)
                            assert response.status_code == 200
                            
                            # Parse response
                            data = response.json()
                            
                            # Verify static analysis is present
                            assert "analysis" in data
                            assert data["analysis"]["risk_score"] == 45
                            
                            # Verify dynamic_status indicates timeout
                            assert "dynamic_status" in data
                            assert data["dynamic_status"] == "TIMEOUT"
                            
                            # Verify dynamic fields are None (no results due to timeout)
                            assert data["contract_id"] is None
                            assert data["dynamic_audit_log"] is None
                            assert data["anomalies_found"] is None
                            assert data["dynamic_risk_adjustment"] is None
                            
                            # Verify PDF and IPFS fields are still present
                            assert "pdf_url" in data
                            assert "cid" in data
                            assert "report_id" in data


def test_dynamic_partial_failure_returns_200(
    client,
    sample_contract_code,
    sample_static_analysis
):
    """
    Test that when dynamic analysis partially fails (e.g., HORIZON_UNAVAILABLE),
    the endpoint returns HTTP 200 with the appropriate dynamic_status.
    
    Validates: Requirements 5.3, 13.3, 13.4
    """
    # Create a partial failure response (deployment succeeded but Horizon failed)
    partial_failure = DynamicAnalyzeResponse(
        contract_id="CTEST123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        dynamic_audit_log=[
            DynamicLogEntry(
                timestamp="2025-04-30T14:23:11Z",
                transaction_hash="tx_hash_001",
                function_called="hello",
                parameters={"to": "World"},
                result="Hello",
                error=None,
                anomaly=False,
                severity="NONE",
                status="NORMAL",
                reason=""
            )
        ],
        anomalies_found=0,
        dynamic_risk_adjustment=0,
        dynamic_status="HORIZON_UNAVAILABLE"
    )
    
    # Mock the static analyzer
    with patch("app.routers.analyze.analyze_contract") as mock_static:
        mock_static.return_value = sample_static_analysis
        
        # Mock the dynamic analyzer to return partial failure
        with patch("app.routers.analyze.run_dynamic_analysis") as mock_dynamic:
            mock_dynamic.return_value = partial_failure
            
            # Mock PDF generation and IPFS upload
            with patch("app.routers.analyze.generate_audit_report") as mock_pdf:
                mock_pdf.return_value = ("/tmp/report.pdf", "report_123")
                
                with patch("app.routers.analyze.upload_pdf_to_ipfs") as mock_ipfs:
                    mock_ipfs.return_value = {
                        "url": "https://ipfs.io/ipfs/QmTest",
                        "cid": "QmTest"
                    }
                    
                    with patch("app.routers.analyze.generate_contract_and_pdf_hashes") as mock_hash:
                        mock_hash.return_value = {
                            "contract_hash": "abc123",
                            "pdf_hash": "def456"
                        }
                        
                        # Make the request
                        response = client.post(
                            "/analyze/",
                            json={
                                "contract_code": sample_contract_code,
                                "contract_name": "TestContract"
                            }
                        )
                        
                        # Should return HTTP 200
                        assert response.status_code == 200
                        
                        # Parse response
                        data = response.json()
                        
                        # Verify static analysis is present
                        assert "analysis" in data
                        assert data["analysis"]["risk_score"] == 45
                        
                        # Verify dynamic_status indicates Horizon unavailable
                        assert data["dynamic_status"] == "HORIZON_UNAVAILABLE"
                        
                        # Verify partial dynamic results are present
                        assert data["contract_id"] == "CTEST123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        assert len(data["dynamic_audit_log"]) == 1
                        assert data["anomalies_found"] == 0
                        assert data["dynamic_risk_adjustment"] == 0
