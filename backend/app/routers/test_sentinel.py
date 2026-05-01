"""
Unit tests for the sentinel router.

Tests:
- test_stream_404_no_monitor: GET /sentinel/stream/unknown → 404
- test_stream_sse_format: verify SSE data lines are valid JSON with required fields
"""

import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.services.sentinel import active_monitors, SentinelMonitor
from app.models.schemas import AuditBounds, SentinelFeedEntry


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def mock_monitor():
    """Create a mock SentinelMonitor with test data."""
    audit_bounds = AuditBounds(
        max_param_value=10000,
        expected_functions=["transfer", "balance"],
        risk_score=50
    )
    
    monitor = SentinelMonitor(
        contract_id="CTEST123",
        contract_hash="test_hash_123",
        audit_bounds=audit_bounds
    )
    
    # Add some test entries to the monitor's log
    monitor._log = [
        SentinelFeedEntry(
            timestamp="2025-04-30T14:23:11Z",
            event="NORMAL_TX",
            function="transfer",
            params={"from": "ADDR1", "to": "ADDR2", "amount": 100},
            status="NORMAL",
            reason=""
        ),
        SentinelFeedEntry(
            timestamp="2025-04-30T14:23:21Z",
            event="SUSPICIOUS_TX",
            function="unknown_function",
            params={"value": 5000},
            status="SUSPICIOUS",
            reason="Unknown function 'unknown_function' not in expected functions list"
        ),
        SentinelFeedEntry(
            timestamp="2025-04-30T14:23:31Z",
            event="FLAGGED_TX",
            function="transfer",
            params={"from": "ADDR1", "to": "ADDR2", "amount": 999999},
            status="FLAGGED",
            reason="Parameter 'amount' value 999999 exceeds audit-established boundary of 10000"
        )
    ]
    
    return monitor


def test_stream_404_no_monitor(client):
    """
    Test that GET /sentinel/stream/unknown returns HTTP 404
    when no active monitor exists for the contract hash.
    
    Validates: Requirements 7.1, 7.6
    """
    # Ensure no monitor exists for this hash
    unknown_hash = "nonexistent_contract_hash"
    if unknown_hash in active_monitors:
        del active_monitors[unknown_hash]
    
    # Request stream for unknown contract
    response = client.get(f"/sentinel/stream/{unknown_hash}")
    
    # Should return 404
    assert response.status_code == 404
    assert "No active sentinel" in response.json()["detail"]


def test_stream_sse_format(client, mock_monitor):
    """
    Test that SSE stream returns valid JSON data lines with required fields.
    
    Validates: Requirements 7.1, 7.4
    """
    # Register the mock monitor
    contract_hash = "test_hash_123"
    active_monitors[contract_hash] = mock_monitor
    
    try:
        # Open SSE stream with timeout to prevent hanging
        with client.stream("GET", f"/sentinel/stream/{contract_hash}", timeout=5.0) as response:
            # Should return 200 with correct content type
            assert response.status_code == 200
            assert response.headers["content-type"] == "text/event-stream; charset=utf-8"
            assert response.headers["cache-control"] == "no-cache"
            assert response.headers["x-accel-buffering"] == "no"
            
            # Read the first few SSE data lines
            entries_parsed = 0
            
            # Use iter_lines() but break after getting all test entries
            for line in response.iter_lines():
                # Decode bytes to string if needed
                if isinstance(line, bytes):
                    line = line.decode('utf-8')
                
                # SSE format: "data: {json}\n\n"
                if line.startswith("data: "):
                    data_json = line[6:]  # Remove "data: " prefix
                    
                    # Parse JSON
                    entry = json.loads(data_json)
                    
                    # Verify required fields are present
                    assert "timestamp" in entry
                    assert "event" in entry
                    assert "function" in entry
                    assert "params" in entry
                    assert "status" in entry
                    assert "reason" in entry
                    
                    # Verify field types
                    assert isinstance(entry["timestamp"], str)
                    assert isinstance(entry["event"], str)
                    assert isinstance(entry["function"], str)
                    assert isinstance(entry["params"], dict)
                    assert isinstance(entry["status"], str)
                    assert isinstance(entry["reason"], str)
                    
                    # Verify status is valid
                    assert entry["status"] in ["NORMAL", "SUSPICIOUS", "FLAGGED"]
                    
                    # Verify event matches status
                    if entry["status"] == "NORMAL":
                        assert entry["event"] == "NORMAL_TX"
                    elif entry["status"] == "SUSPICIOUS":
                        assert entry["event"] == "SUSPICIOUS_TX"
                    elif entry["status"] == "FLAGGED":
                        assert entry["event"] == "FLAGGED_TX"
                    
                    entries_parsed += 1
                    
                    # CRITICAL: Stop after parsing 3 entries to prevent infinite loop
                    if entries_parsed >= 3:
                        break
            
            # Should have parsed all 3 test entries
            assert entries_parsed == 3
    
    finally:
        # Cleanup: remove the mock monitor
        if contract_hash in active_monitors:
            del active_monitors[contract_hash]


def test_stream_sse_format_empty_reason_for_normal(client, mock_monitor):
    """
    Test that NORMAL entries have empty reason field.
    
    Validates: Requirements 14.3
    """
    # Register the mock monitor
    contract_hash = "test_hash_456"
    active_monitors[contract_hash] = mock_monitor
    
    try:
        # Open SSE stream with timeout
        with client.stream("GET", f"/sentinel/stream/{contract_hash}", timeout=5.0) as response:
            assert response.status_code == 200
            
            # Read first entry (should be NORMAL)
            found_normal = False
            for line in response.iter_lines():
                # Decode bytes to string if needed
                if isinstance(line, bytes):
                    line = line.decode('utf-8')
                
                if line.startswith("data: "):
                    data_json = line[6:]
                    entry = json.loads(data_json)
                    
                    if entry["status"] == "NORMAL":
                        # NORMAL entries should have empty reason
                        assert entry["reason"] == ""
                        found_normal = True
                        break  # CRITICAL: Exit after finding what we need
            
            assert found_normal, "Should have found at least one NORMAL entry"
    
    finally:
        # Cleanup
        if contract_hash in active_monitors:
            del active_monitors[contract_hash]


def test_stream_sse_format_nonempty_reason_for_flagged(client, mock_monitor):
    """
    Test that FLAGGED entries have non-empty reason field.
    
    Validates: Requirements 14.2
    """
    # Register the mock monitor
    contract_hash = "test_hash_789"
    active_monitors[contract_hash] = mock_monitor
    
    try:
        # Open SSE stream with timeout
        with client.stream("GET", f"/sentinel/stream/{contract_hash}", timeout=5.0) as response:
            assert response.status_code == 200
            
            # Read entries until we find a FLAGGED one
            found_flagged = False
            for line in response.iter_lines():
                # Decode bytes to string if needed
                if isinstance(line, bytes):
                    line = line.decode('utf-8')
                
                if line.startswith("data: "):
                    data_json = line[6:]
                    entry = json.loads(data_json)
                    
                    if entry["status"] == "FLAGGED":
                        # FLAGGED entries must have non-empty reason
                        assert entry["reason"] != ""
                        assert len(entry["reason"]) > 0
                        found_flagged = True
                        break  # CRITICAL: Exit after finding what we need
            
            assert found_flagged, "Should have found at least one FLAGGED entry"
    
    finally:
        # Cleanup
        if contract_hash in active_monitors:
            del active_monitors[contract_hash]
