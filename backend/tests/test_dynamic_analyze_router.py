"""
Unit tests for the dynamic_analyze router.

Tests the POST /dynamic-analyze/ endpoint to ensure it properly handles
requests and never returns HTTP 500 errors.

**Validates: Requirements 1.1, 1.5, 1.6, 1.7**
"""

from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from app.models.schemas import DynamicAnalyzeResponse


client = TestClient(app)


def test_dynamic_analyze_empty_contract_code():
    """
    Test that empty contract code returns DEPLOY_FAILED status, not HTTP 400.
    
    **Validates: Requirement 1.6**
    """
    response = client.post(
        "/dynamic-analyze/",
        json={
            "contract_code": "",
            "contract_hash": "abc123"
        }
    )
    
    assert response.status_code == 200, "Should return 200 even for empty contract"
    data = response.json()
    
    assert data["dynamic_status"] == "DEPLOY_FAILED"
    assert data["contract_id"] is None
    assert data["dynamic_audit_log"] == []
    assert data["anomalies_found"] == 0
    assert data["dynamic_risk_adjustment"] == 0


def test_dynamic_analyze_success():
    """
    Test that successful dynamic analysis returns proper response structure.
    
    **Validates: Requirements 1.1, 1.5**
    """
    with patch('app.routers.dynamic_analyze.run_dynamic_analysis') as mock_run_analysis:
        # Mock successful analysis
        mock_run_analysis.return_value = DynamicAnalyzeResponse(
            contract_id="CTEST123",
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="OK"
        )
        
        response = client.post(
            "/dynamic-analyze/",
            json={
                "contract_code": "test contract code",
                "contract_name": "TestContract",
                "contract_hash": "abc123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["contract_id"] == "CTEST123"
        assert data["dynamic_status"] == "OK"
        assert data["anomalies_found"] == 0
        assert data["dynamic_risk_adjustment"] == 0


def test_dynamic_analyze_exception_returns_200():
    """
    Test that exceptions in dynamic analysis return 200 with DEPLOY_FAILED status.
    
    **Validates: Requirement 1.7 - Never return HTTP 500**
    """
    with patch('app.routers.dynamic_analyze.run_dynamic_analysis') as mock_run_analysis:
        # Mock exception
        mock_run_analysis.side_effect = Exception("Test exception")
        
        response = client.post(
            "/dynamic-analyze/",
            json={
                "contract_code": "test contract code",
                "contract_hash": "abc123"
            }
        )
        
        assert response.status_code == 200, "Should return 200 even on exception"
        data = response.json()
        
        assert data["dynamic_status"] == "DEPLOY_FAILED"
        assert data["contract_id"] is None
        assert data["dynamic_audit_log"] == []


def test_dynamic_analyze_deploy_failed():
    """
    Test that deployment failures are properly encoded in response.
    
    **Validates: Requirement 1.6**
    """
    with patch('app.routers.dynamic_analyze.run_dynamic_analysis') as mock_run_analysis:
        # Mock deployment failure
        mock_run_analysis.return_value = DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="DEPLOY_FAILED"
        )
        
        response = client.post(
            "/dynamic-analyze/",
            json={
                "contract_code": "invalid contract code",
                "contract_hash": "abc123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["dynamic_status"] == "DEPLOY_FAILED"
        assert data["contract_id"] is None


def test_dynamic_analyze_horizon_unavailable():
    """
    Test that Horizon API failures are properly encoded in response.
    
    **Validates: Requirement 1.7**
    """
    with patch('app.routers.dynamic_analyze.run_dynamic_analysis') as mock_run_analysis:
        # Mock Horizon unavailable
        mock_run_analysis.return_value = DynamicAnalyzeResponse(
            contract_id="CTEST123",
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="HORIZON_UNAVAILABLE"
        )
        
        response = client.post(
            "/dynamic-analyze/",
            json={
                "contract_code": "test contract code",
                "contract_hash": "abc123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["dynamic_status"] == "HORIZON_UNAVAILABLE"
        assert data["contract_id"] == "CTEST123"


def test_dynamic_analyze_timeout():
    """
    Test that timeout is properly encoded in response.
    
    **Validates: Requirement 1.7**
    """
    with patch('app.routers.dynamic_analyze.run_dynamic_analysis') as mock_run_analysis:
        # Mock timeout
        mock_run_analysis.return_value = DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="TIMEOUT"
        )
        
        response = client.post(
            "/dynamic-analyze/",
            json={
                "contract_code": "test contract code",
                "contract_hash": "abc123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["dynamic_status"] == "TIMEOUT"
        assert data["contract_id"] is None


def test_dynamic_analyze_missing_contract_hash():
    """
    Test that missing contract_hash returns proper validation error.
    """
    response = client.post(
        "/dynamic-analyze/",
        json={
            "contract_code": "test contract code"
            # Missing contract_hash
        }
    )
    
    # FastAPI validation should return 422 for missing required field
    assert response.status_code == 422


def test_dynamic_analyze_default_contract_name():
    """
    Test that contract_name defaults to "Unknown Contract" when not provided.
    
    **Validates: Requirement 1.1**
    """
    with patch('app.routers.dynamic_analyze.run_dynamic_analysis') as mock_run:
        mock_run.return_value = DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="DEPLOY_FAILED"
        )
        
        response = client.post(
            "/dynamic-analyze/",
            json={
                "contract_code": "test",
                "contract_hash": "abc123"
                # No contract_name provided
            }
        )
        
        assert response.status_code == 200
        
        # Verify run_dynamic_analysis was called with default name
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[1]["contract_name"] == "Unknown Contract"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
