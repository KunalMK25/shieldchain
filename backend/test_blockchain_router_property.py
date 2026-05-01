"""
Property-based tests for blockchain router endpoints.

Feature: shieldchain-full-stack
Property 5: Anchor response always contains `tx_hash` and `timestamp`
Property 6: Fallback always returns a valid explorer URL
"""

import pytest
from hypothesis import given, settings, strategies as st
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app
from app.models.schemas import AnchorRequest
import hashlib


client = TestClient(app)


# Strategy for generating valid contract hashes (64-char hex strings)
contract_hash_strategy = st.text(
    alphabet="0123456789abcdef",
    min_size=64,
    max_size=64
)

# Strategy for generating valid report hashes (64-char hex strings)
report_hash_strategy = st.text(
    alphabet="0123456789abcdef",
    min_size=64,
    max_size=64
)

# Strategy for generating valid risk scores (0-100)
risk_score_strategy = st.integers(min_value=0, max_value=100)

# Strategy for generating non-empty IPFS CIDs
ipfs_cid_strategy = st.text(
    alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    min_size=46,
    max_size=46
).map(lambda s: "Qm" + s)


@settings(max_examples=20, deadline=None)
@given(
    contract_hash=contract_hash_strategy,
    report_hash=report_hash_strategy,
    risk_score=risk_score_strategy,
    ipfs_cid=ipfs_cid_strategy,
    should_succeed=st.booleans()
)
@patch("app.routers.blockchain.get_history")
@patch("app.routers.blockchain.send_audit_to_soroban")
@patch("app.routers.blockchain.register_audit")
def test_property_5_anchor_response_contains_tx_hash_and_timestamp(
    mock_register_audit,
    mock_send_audit,
    mock_get_history,
    contract_hash,
    report_hash,
    risk_score,
    ipfs_cid,
    should_succeed
):
    """
    Property 5: Anchor response always contains `tx_hash` and `timestamp`
    
    For any valid anchor request (any contract_hash, report_hash, risk_score in [0, 100],
    non-empty ipfs_cid), the /blockchain/anchor endpoint SHALL return a response containing
    a non-empty tx_hash string and a non-empty timestamp string, regardless of whether the
    Soroban invocation succeeds or falls back to the local store.
    
    **Validates: Requirements 3.1, 3.9**
    """
    # Mock get_history to return empty list (no existing anchors)
    mock_get_history.return_value = []
    
    # Mock send_audit_to_soroban to either succeed or fail based on should_succeed
    if should_succeed:
        # Simulate successful Soroban anchoring
        mock_tx_hash = hashlib.sha256(f"{contract_hash}{ipfs_cid}".encode()).hexdigest()
        mock_send_audit.return_value = mock_tx_hash
    else:
        # Simulate Soroban failure (fallback scenario)
        mock_send_audit.side_effect = RuntimeError("Soroban invocation failed")
        mock_register_audit.return_value = {
            "audit_id": "test_audit_id",
            "contract_hash": contract_hash,
            "report_hash": report_hash,
            "risk_score": risk_score,
            "ipfs_cid": ipfs_cid,
            "auditor": "local-dev",
            "created_at": "2026-04-30T12:00:00Z",
            "source": "local-store"
        }
    
    # Make the request
    request_data = {
        "contract_hash": contract_hash,
        "report_hash": report_hash,
        "risk_score": risk_score,
        "ipfs_cid": ipfs_cid,
        "contract_name": "Test Contract"
    }
    
    response = client.post("/blockchain/anchor", json=request_data)
    
    # Assert response is successful
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    
    # Parse response
    data = response.json()
    
    # Property assertion: response MUST contain non-empty tx_hash and timestamp
    assert "tx_hash" in data, "Response missing tx_hash field"
    assert "timestamp" in data, "Response missing timestamp field"
    assert isinstance(data["tx_hash"], str), "tx_hash must be a string"
    assert isinstance(data["timestamp"], str), "timestamp must be a string"
    assert len(data["tx_hash"]) > 0, "tx_hash must be non-empty"
    assert len(data["timestamp"]) > 0, "timestamp must be non-empty"
    
    # Additional validation: check source field is correct
    if should_succeed:
        assert data["source"] == "stellar", "Source should be 'stellar' on success"
    else:
        assert data["source"] == "local-fallback", "Source should be 'local-fallback' on failure"


@settings(max_examples=20, deadline=None)
@given(
    tx_hash=st.text(
        alphabet="0123456789abcdef",
        min_size=1,
        max_size=64
    )
)
def test_property_6_explorer_url_format(tx_hash):
    """
    Property 6: Fallback always returns a valid explorer URL
    
    For any tx_hash string (whether a real Stellar transaction hash or a simulated demo hash),
    the explorer_url field in the anchor response SHALL equal
    "https://stellar.expert/explorer/testnet/tx/" + tx_hash exactly.
    
    **Validates: Requirements 3.2, 3.9**
    """
    # Generate a valid anchor request
    contract_hash = "a" * 64
    report_hash = "b" * 64
    risk_score = 50
    ipfs_cid = "QmTest123456789012345678901234567890123456"
    
    with patch("app.routers.blockchain.get_history") as mock_get_history, \
         patch("app.routers.blockchain.send_audit_to_soroban") as mock_send_audit, \
         patch("app.routers.blockchain.register_audit") as mock_register_audit:
        
        # Mock get_history to return empty list
        mock_get_history.return_value = []
        
        # Mock send_audit_to_soroban to return our test tx_hash
        mock_send_audit.return_value = tx_hash
        
        # Make the request
        request_data = {
            "contract_hash": contract_hash,
            "report_hash": report_hash,
            "risk_score": risk_score,
            "ipfs_cid": ipfs_cid,
            "contract_name": "Test Contract"
        }
        
        response = client.post("/blockchain/anchor", json=request_data)
        
        # Assert response is successful
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        # Parse response
        data = response.json()
        
        # Property assertion: explorer_url MUST equal the expected format exactly
        expected_url = f"https://stellar.expert/explorer/testnet/tx/{tx_hash}"
        assert "explorer_url" in data, "Response missing explorer_url field"
        assert data["explorer_url"] == expected_url, \
            f"Explorer URL format incorrect. Expected: {expected_url}, Got: {data['explorer_url']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
