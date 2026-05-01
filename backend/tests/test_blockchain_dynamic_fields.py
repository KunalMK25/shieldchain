"""
Unit tests for blockchain router dynamic fields integration.

Tests that dynamic_anomalies_count and dynamic_risk_adjustment are properly
passed from AnchorRequest to the Soroban contract invocation.

**Validates: Requirements 11.1, 11.2, 11.5**
"""

from pathlib import Path
import sys
from unittest.mock import patch, MagicMock, call

import pytest
from fastapi.testclient import TestClient

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


client = TestClient(app)


@patch('app.routers.blockchain.register_audit')
@patch('app.routers.blockchain.send_audit_to_soroban')
@patch('app.routers.blockchain.get_history')
def test_anchor_with_dynamic_fields(mock_get_history, mock_send_audit, mock_register_audit):
    """
    Test that dynamic_anomalies_count and dynamic_risk_adjustment are passed
    to send_audit_to_soroban when provided in the request.
    
    **Validates: Requirements 11.1, 11.2, 11.5**
    """
    # Mock get_history to return empty (no existing records)
    mock_get_history.return_value = []
    
    # Mock send_audit_to_soroban to succeed
    mock_send_audit.return_value = "abc123def456"
    
    # Make request with dynamic fields
    response = client.post(
        "/blockchain/anchor",
        json={
            "contract_hash": "dynamic123",
            "report_hash": "dynamicreport456",
            "risk_score": 75,
            "ipfs_cid": "QmDynamic",
            "contract_name": "Dynamic Contract",
            "dynamic_anomalies_count": 3,
            "dynamic_risk_adjustment": 8
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify response structure
    assert data["source"] == "stellar"
    assert "tx_hash" in data
    
    # Verify send_audit_to_soroban was called with dynamic fields
    mock_send_audit.assert_called_once_with(
        "dynamic123",
        "dynamicreport456",
        75,
        "QmDynamic",
        3,  # dynamic_anomalies_count
        8   # dynamic_risk_adjustment
    )


@patch('app.routers.blockchain.register_audit')
@patch('app.routers.blockchain.send_audit_to_soroban')
@patch('app.routers.blockchain.get_history')
def test_anchor_without_dynamic_fields_defaults_to_zero(mock_get_history, mock_send_audit, mock_register_audit):
    """
    Test that when dynamic fields are not provided, they default to 0.
    
    **Validates: Requirements 11.2**
    """
    # Mock get_history to return empty (no existing records)
    mock_get_history.return_value = []
    
    # Mock send_audit_to_soroban to succeed
    mock_send_audit.return_value = "xyz789abc012"
    
    # Make request WITHOUT dynamic fields
    response = client.post(
        "/blockchain/anchor",
        json={
            "contract_hash": "nodynamic123",
            "report_hash": "nodynamic456",
            "risk_score": 50,
            "ipfs_cid": "QmNoDynamic",
            "contract_name": "No Dynamic Contract"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify response structure
    assert data["source"] == "stellar"
    assert "tx_hash" in data
    
    # Verify send_audit_to_soroban was called with default values (0, 0)
    mock_send_audit.assert_called_once_with(
        "nodynamic123",
        "nodynamic456",
        50,
        "QmNoDynamic",
        0,  # dynamic_anomalies_count defaults to 0
        0   # dynamic_risk_adjustment defaults to 0
    )


@patch('app.routers.blockchain.register_audit')
@patch('app.routers.blockchain.send_audit_to_soroban')
@patch('app.routers.blockchain.get_history')
def test_anchor_fallback_with_dynamic_fields(mock_get_history, mock_send_audit):
    """
    Test that dynamic fields are handled correctly even when Soroban fails
    and fallback to local store occurs.
    
    **Validates: Requirements 11.2**
    """
    # Mock get_history to return empty (no existing records)
    mock_get_history.return_value = []
    
    # Mock send_audit_to_soroban to fail (Soroban unavailable)
    mock_send_audit.side_effect = RuntimeError("Soroban RPC timeout")
    
    # Make request with dynamic fields
    response = client.post(
        "/blockchain/anchor",
        json={
            "contract_hash": "fallbackdynamic123",
            "report_hash": "fallbackdynamic456",
            "risk_score": 85,
            "ipfs_cid": "QmFallbackDynamic",
            "contract_name": "Fallback Dynamic Contract",
            "dynamic_anomalies_count": 5,
            "dynamic_risk_adjustment": 12
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify fallback behavior
    assert data["source"] == "local-fallback"
    assert "tx_hash" in data
    assert data["tx_hash"].startswith("demo_")
    
    # Verify send_audit_to_soroban was called with dynamic fields (even though it failed)
    mock_send_audit.assert_called_once_with(
        "fallbackdynamic123",
        "fallbackdynamic456",
        85,
        "QmFallbackDynamic",
        5,  # dynamic_anomalies_count
        12  # dynamic_risk_adjustment
    )
    
    # Note: We don't check for register_audit call anymore since the code
    # writes directly to the audit store file for better control


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
