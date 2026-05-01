"""
Unit tests for blockchain router endpoints.

Tests error handling, fallback behavior, and edge cases for blockchain anchoring.

**Validates: Requirements 3.3, 3.4, 3.6, 3.9**
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


@patch('app.routers.blockchain.get_history')
@patch('app.routers.blockchain.send_audit_to_soroban')
def test_anchor_duplicate(mock_send_audit, mock_get_history):
    """
    Test that anchoring the same hash twice returns 409.
    
    **Validates: Requirement 3.4**
    """
    # Mock get_history to return existing records (indicating already anchored)
    mock_get_history.return_value = [
        {
            "contract_hash": "abc123",
            "report_hash": "def456",
            "risk_score": 50,
            "ipfs_cid": "QmTest",
            "auditor": "test-auditor",
            "created_at": "2026-04-30T12:00:00Z",
            "source": "stellar"
        }
    ]
    
    # Attempt to anchor the same contract hash
    response = client.post(
        "/blockchain/anchor",
        json={
            "contract_hash": "abc123",
            "report_hash": "ghi789",
            "risk_score": 60,
            "ipfs_cid": "QmTest2",
            "contract_name": "Duplicate Contract"
        }
    )
    
    assert response.status_code == 409
    assert "detail" in response.json()
    assert "already anchored" in response.json()["detail"].lower()
    
    # Verify send_audit_to_soroban was NOT called (early exit on duplicate check)
    mock_send_audit.assert_not_called()


@patch('app.routers.blockchain.get_audit_from_soroban')
@patch('app.routers.blockchain.get_history')
def test_verify_not_found(mock_get_history, mock_get_audit):
    """
    Test that GET /blockchain/verify/unknownhash returns 404.
    
    **Validates: Requirement 3.6**
    """
    # Mock get_audit_from_soroban to raise RuntimeError (not found on chain)
    mock_get_audit.side_effect = RuntimeError("Audit not found on Soroban")
    
    # Mock get_history to return empty list (not found in local store)
    mock_get_history.return_value = []
    
    response = client.get("/blockchain/verify/unknownhash")
    
    assert response.status_code == 404
    assert "detail" in response.json()
    assert "not found" in response.json()["detail"].lower()


@patch('app.routers.blockchain.register_audit')
@patch('app.routers.blockchain.send_audit_to_soroban')
@patch('app.routers.blockchain.get_history')
def test_soroban_fallback(mock_get_history, mock_send_audit, mock_register_audit):
    """
    Test that when send_audit_to_soroban raises RuntimeError,
    the response has source == "local-fallback".
    
    **Validates: Requirement 3.9**
    """
    # Mock get_history to return empty (no existing records)
    mock_get_history.return_value = []
    
    # Mock send_audit_to_soroban to raise RuntimeError (Soroban failure)
    mock_send_audit.side_effect = RuntimeError("Soroban RPC timeout")
    
    # Mock register_audit to succeed (local fallback)
    mock_register_audit.return_value = None
    
    response = client.post(
        "/blockchain/anchor",
        json={
            "contract_hash": "fallback123",
            "report_hash": "fallback456",
            "risk_score": 75,
            "ipfs_cid": "QmFallback",
            "contract_name": "Fallback Contract"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verify fallback behavior
    assert data["source"] == "local-fallback"
    assert "tx_hash" in data
    assert data["tx_hash"].startswith("demo_")
    assert "explorer_url" in data
    assert "stellar.expert/explorer/testnet/tx/" in data["explorer_url"]
    
    # Verify register_audit was called (fallback to local store)
    mock_register_audit.assert_called_once()


@patch('app.routers.blockchain.get_history')
def test_history_empty(mock_get_history):
    """
    Test that GET /blockchain/history/unknownhash returns 200 with empty list.
    
    **Validates: Requirement 3.7**
    """
    # Mock get_history to return empty list
    mock_get_history.return_value = []
    
    response = client.get("/blockchain/history/unknownhash")
    
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, list)
    assert len(data) == 0


@patch('app.routers.blockchain.get_history')
def test_history_with_records(mock_get_history):
    """
    Test that GET /blockchain/history returns records sorted by created_at descending.
    
    This is a positive test to verify the sorting behavior.
    """
    # Mock get_history to return multiple records
    mock_get_history.return_value = [
        {
            "contract_hash": "test123",
            "report_hash": "report1",
            "risk_score": 50,
            "ipfs_cid": "QmTest1",
            "auditor": "auditor1",
            "created_at": "2026-04-30T10:00:00Z",
            "source": "stellar"
        },
        {
            "contract_hash": "test123",
            "report_hash": "report2",
            "risk_score": 40,
            "ipfs_cid": "QmTest2",
            "auditor": "auditor2",
            "created_at": "2026-04-30T12:00:00Z",
            "source": "stellar"
        },
        {
            "contract_hash": "test123",
            "report_hash": "report3",
            "risk_score": 30,
            "ipfs_cid": "QmTest3",
            "auditor": "auditor3",
            "created_at": "2026-04-30T11:00:00Z",
            "source": "local-store"
        }
    ]
    
    response = client.get("/blockchain/history/test123")
    
    assert response.status_code == 200
    data = response.json()
    
    assert isinstance(data, list)
    assert len(data) == 3
    
    # Verify sorting: most recent first
    assert data[0]["created_at"] == "2026-04-30T12:00:00Z"
    assert data[1]["created_at"] == "2026-04-30T11:00:00Z"
    assert data[2]["created_at"] == "2026-04-30T10:00:00Z"
    
    # Verify all required fields are present
    for record in data:
        assert "contract_hash" in record
        assert "report_hash" in record
        assert "risk_score" in record
        assert "auditor" in record
        assert "created_at" in record
        assert "source" in record


@patch('app.routers.blockchain.get_audit_from_soroban')
def test_verify_from_stellar(mock_get_audit):
    """
    Test successful verification from Stellar blockchain.
    
    This is a positive test to verify the stellar source path.
    """
    # Mock get_audit_from_soroban to return valid audit data
    mock_get_audit.return_value = {
        "contract_hash": "stellar123",
        "report_hash": "stellarreport",
        "risk_score": 65,
        "ipfs_cid": "QmStellar",
        "timestamp": 1714478400,
        "auditor": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    }
    
    response = client.get("/blockchain/verify/stellar123")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["source"] == "stellar"
    assert data["contract_hash"] == "stellar123"
    assert data["risk_score"] == 65
    assert data["ipfs_cid"] == "QmStellar"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
