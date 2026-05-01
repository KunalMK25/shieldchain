"""
Unit tests for SentinelMonitor service.

Feature: dynamic-analysis-sentinel-audit

**Validates: Requirements 6.7, 6.8**
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.sentinel import SentinelMonitor, active_monitors
from app.models.schemas import AuditBounds, SentinelFeedEntry


@pytest.fixture
def audit_bounds():
    """Fixture providing sample audit bounds."""
    return AuditBounds(
        max_param_value=10000,
        expected_functions=["transfer", "mint", "burn"],
        risk_score=50
    )


@pytest.fixture
def sentinel_monitor(audit_bounds):
    """Fixture providing a SentinelMonitor instance."""
    return SentinelMonitor(
        contract_id="CTEST123456789",
        contract_hash="abc123def456",
        audit_bounds=audit_bounds
    )


@pytest.mark.asyncio
async def test_stream_continues_on_horizon_failure(sentinel_monitor):
    """
    Test that SentinelMonitor continues polling even when Horizon API fails.
    
    Mock Horizon to fail, verify monitor keeps running and doesn't crash.
    
    **Validates: Requirements 6.7, 6.8**
    """
    # Mock the Horizon client to raise an exception
    sentinel_monitor._horizon.poll_contract_transactions = AsyncMock(
        side_effect=Exception("Horizon API unavailable")
    )
    
    # Start the monitor in a background task
    monitor_task = asyncio.create_task(sentinel_monitor.start_monitoring())
    
    # Let it run for a short time (enough for 2-3 poll attempts)
    await asyncio.sleep(0.5)
    
    # Verify the monitor is still running (hasn't crashed)
    assert sentinel_monitor._running is True, \
        "Monitor should still be running after Horizon failures"
    
    # Stop the monitor
    sentinel_monitor.stop()
    
    # Wait for the task to complete
    await asyncio.sleep(0.2)
    
    # Verify it stopped gracefully
    assert sentinel_monitor._running is False, \
        "Monitor should have stopped after stop() was called"
    
    # Cancel the task if it's still running
    if not monitor_task.done():
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


def test_get_live_feed_returns_snapshot(sentinel_monitor):
    """
    Test that get_live_feed returns a copy, not a reference.
    
    Verify returned list is a copy that can be modified without affecting
    the internal log.
    
    **Validates: Requirements 6.7**
    """
    # Add some entries to the internal log
    entry1 = SentinelFeedEntry(
        timestamp="2025-04-30T14:23:11Z",
        event="NORMAL_TX",
        function="transfer",
        params={"amount": 100},
        status="NORMAL",
        reason=""
    )
    entry2 = SentinelFeedEntry(
        timestamp="2025-04-30T14:23:21Z",
        event="SUSPICIOUS_TX",
        function="mint",
        params={"amount": 50000},
        status="SUSPICIOUS",
        reason="Amount exceeds boundary"
    )
    
    sentinel_monitor._log.append(entry1)
    sentinel_monitor._log.append(entry2)
    
    # Get the live feed
    feed = sentinel_monitor.get_live_feed()
    
    # Verify it's a copy (same content)
    assert len(feed) == 2, "Feed should contain 2 entries"
    assert feed[0] == entry1, "First entry should match"
    assert feed[1] == entry2, "Second entry should match"
    
    # Modify the returned list
    feed.append(SentinelFeedEntry(
        timestamp="2025-04-30T14:23:31Z",
        event="FLAGGED_TX",
        function="burn",
        params={"amount": 999999},
        status="FLAGGED",
        reason="Critical violation"
    ))
    
    # Verify the internal log was not affected
    assert len(sentinel_monitor._log) == 2, \
        "Internal log should still have 2 entries (not affected by modification of returned list)"
    
    # Verify we can get a fresh copy
    feed2 = sentinel_monitor.get_live_feed()
    assert len(feed2) == 2, "Fresh copy should have 2 entries"
    assert feed2 is not feed, "Each call should return a new copy"


def test_check_boundary_violations_unknown_function(sentinel_monitor):
    """
    Test that _check_boundary_violations flags unknown functions.
    
    **Validates: Requirements 6.3**
    """
    # Transaction with unknown function
    tx = {
        "function": "unknown_function",
        "parameters": {"amount": 100}
    }
    
    is_suspicious, reason = sentinel_monitor._check_boundary_violations(tx)
    
    assert is_suspicious is True, "Unknown function should be flagged"
    assert reason != "", "Reason should be non-empty"
    assert "unknown_function" in reason or "Unknown function" in reason, \
        f"Reason should mention the unknown function: {reason}"


def test_check_boundary_violations_exceeds_max_param(sentinel_monitor):
    """
    Test that _check_boundary_violations flags parameter values exceeding max.
    
    **Validates: Requirements 6.4**
    """
    # Transaction with parameter exceeding max_param_value (10000)
    tx = {
        "function": "transfer",
        "parameters": {"amount": 50000}
    }
    
    is_suspicious, reason = sentinel_monitor._check_boundary_violations(tx)
    
    assert is_suspicious is True, "Parameter exceeding max should be flagged"
    assert reason != "", "Reason should be non-empty"
    assert "10000" in reason, f"Reason should mention the boundary value: {reason}"
    assert "amount" in reason or "Parameter" in reason, \
        f"Reason should mention the parameter: {reason}"


def test_check_boundary_violations_no_violations(sentinel_monitor):
    """
    Test that _check_boundary_violations returns False when no violations.
    
    **Validates: Requirements 6.3, 6.4**
    """
    # Transaction with known function and parameter within bounds
    tx = {
        "function": "transfer",
        "parameters": {"amount": 5000}
    }
    
    is_suspicious, reason = sentinel_monitor._check_boundary_violations(tx)
    
    assert is_suspicious is False, "No violations should not be flagged"
    assert reason == "", "Reason should be empty when no violations"


def test_build_feed_entry_normal(sentinel_monitor):
    """
    Test that _build_feed_entry correctly builds a NORMAL entry.
    
    **Validates: Requirements 14.1, 14.4**
    """
    tx = {
        "function": "transfer",
        "parameters": {"amount": 100},
        "created_at": "2025-04-30T14:23:11Z"
    }
    
    entry = sentinel_monitor._build_feed_entry(tx, "NORMAL", "")
    
    assert entry.event == "NORMAL_TX", "Event should be NORMAL_TX"
    assert entry.status == "NORMAL", "Status should be NORMAL"
    assert entry.function == "transfer", "Function should match"
    assert entry.params == {"amount": 100}, "Params should match"
    assert entry.reason == "", "Reason should be empty for NORMAL"
    assert entry.timestamp == "2025-04-30T14:23:11Z", "Timestamp should match"


def test_build_feed_entry_suspicious(sentinel_monitor):
    """
    Test that _build_feed_entry correctly builds a SUSPICIOUS entry.
    
    **Validates: Requirements 14.1, 14.4**
    """
    tx = {
        "function": "mint",
        "parameters": {"amount": 50000},
        "created_at": "2025-04-30T14:23:21Z"
    }
    
    entry = sentinel_monitor._build_feed_entry(
        tx,
        "SUSPICIOUS",
        "Amount exceeds boundary"
    )
    
    assert entry.event == "SUSPICIOUS_TX", "Event should be SUSPICIOUS_TX"
    assert entry.status == "SUSPICIOUS", "Status should be SUSPICIOUS"
    assert entry.function == "mint", "Function should match"
    assert entry.params == {"amount": 50000}, "Params should match"
    assert entry.reason == "Amount exceeds boundary", "Reason should match"
    assert entry.timestamp == "2025-04-30T14:23:21Z", "Timestamp should match"


def test_build_feed_entry_flagged(sentinel_monitor):
    """
    Test that _build_feed_entry correctly builds a FLAGGED entry.
    
    **Validates: Requirements 14.1, 14.2, 14.4**
    """
    tx = {
        "function": "burn",
        "parameters": {"amount": 999999},
        "created_at": "2025-04-30T14:23:31Z"
    }
    
    entry = sentinel_monitor._build_feed_entry(
        tx,
        "FLAGGED",
        "Critical security violation detected"
    )
    
    assert entry.event == "FLAGGED_TX", "Event should be FLAGGED_TX"
    assert entry.status == "FLAGGED", "Status should be FLAGGED"
    assert entry.function == "burn", "Function should match"
    assert entry.params == {"amount": 999999}, "Params should match"
    assert entry.reason == "Critical security violation detected", "Reason should match"
    assert entry.reason != "", "Reason should be non-empty for FLAGGED"
    assert entry.timestamp == "2025-04-30T14:23:31Z", "Timestamp should match"


def test_build_feed_entry_missing_timestamp(sentinel_monitor):
    """
    Test that _build_feed_entry generates timestamp when missing.
    
    **Validates: Requirements 14.5**
    """
    tx = {
        "function": "transfer",
        "parameters": {"amount": 100}
        # No created_at field
    }
    
    entry = sentinel_monitor._build_feed_entry(tx, "NORMAL", "")
    
    assert entry.timestamp != "", "Timestamp should not be empty"
    # Verify it's a valid ISO-8601 timestamp
    from datetime import datetime
    try:
        datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
    except ValueError:
        pytest.fail(f"Generated timestamp '{entry.timestamp}' is not valid ISO-8601")


def test_stop_sets_running_false(sentinel_monitor):
    """
    Test that stop() sets _running to False.
    
    **Validates: Requirements 6.8**
    """
    # Initially not running
    assert sentinel_monitor._running is False
    
    # Simulate starting
    sentinel_monitor._running = True
    assert sentinel_monitor._running is True
    
    # Call stop
    sentinel_monitor.stop()
    
    # Verify it's stopped
    assert sentinel_monitor._running is False


@pytest.mark.asyncio
async def test_start_monitoring_processes_transactions(sentinel_monitor):
    """
    Test that start_monitoring processes transactions and appends to log.
    
    **Validates: Requirements 6.2, 6.5, 6.6**
    """
    # Mock Horizon to return sample transactions
    mock_transactions = [
        {
            "function": "transfer",
            "parameters": {"amount": 100},
            "created_at": "2025-04-30T14:23:11Z",
            "paging_token": "token1"
        },
        {
            "function": "mint",
            "parameters": {"amount": 50000},
            "created_at": "2025-04-30T14:23:21Z",
            "paging_token": "token2"
        }
    ]
    
    # Mock to return transactions once, then empty list
    call_count = 0
    async def mock_poll(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_transactions
        return []
    
    sentinel_monitor._horizon.poll_contract_transactions = mock_poll
    
    # Start the monitor in a background task
    monitor_task = asyncio.create_task(sentinel_monitor.start_monitoring())
    
    # Let it run for a short time
    await asyncio.sleep(0.3)
    
    # Stop the monitor
    sentinel_monitor.stop()
    await asyncio.sleep(0.2)
    
    # Verify transactions were processed
    feed = sentinel_monitor.get_live_feed()
    assert len(feed) >= 2, f"Should have processed at least 2 transactions, got {len(feed)}"
    
    # Verify first transaction (within bounds)
    assert feed[0].function == "transfer"
    assert feed[0].status == "NORMAL"
    
    # Verify second transaction (exceeds boundary)
    assert feed[1].function == "mint"
    assert feed[1].status == "SUSPICIOUS"
    assert "exceeds" in feed[1].reason.lower() or "boundary" in feed[1].reason.lower()
    
    # Cancel the task if it's still running
    if not monitor_task.done():
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

