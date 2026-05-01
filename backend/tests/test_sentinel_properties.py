"""
Property-based tests for SentinelMonitor service.

Feature: dynamic-analysis-sentinel-audit
Properties 9-13: SentinelMonitor behavior validation

**Validates: Requirements 6.3, 6.4, 14.2, 14.3, 14.4, 14.5**
"""

import pytest
from hypothesis import given, settings, strategies as st
from datetime import datetime, timezone

from app.services.sentinel import SentinelMonitor
from app.models.schemas import AuditBounds, SentinelFeedEntry


@settings(max_examples=100, deadline=None)
@given(
    function_name=st.text(min_size=1, max_size=50),
    expected_functions=st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=10)
)
def test_property_9_sentinel_flags_unknown_functions(
    function_name: str,
    expected_functions: list[str]
):
    """
    Property 9: SentinelMonitor flags unknown functions as SUSPICIOUS
    
    For any SentinelMonitor with any expected_functions list, and any transaction
    where function_called is not in expected_functions, _check_boundary_violations
    must return (True, reason) with a non-empty reason string.
    
    **Validates: Requirements 6.3**
    """
    # Create audit bounds with the expected functions
    audit_bounds = AuditBounds(
        max_param_value=10000,
        expected_functions=expected_functions,
        risk_score=50
    )
    
    # Create SentinelMonitor
    monitor = SentinelMonitor(
        contract_id="CTEST123",
        contract_hash="test_hash",
        audit_bounds=audit_bounds
    )
    
    # Create a transaction with the function name
    tx = {
        "function": function_name,
        "parameters": {}
    }
    
    # Check boundary violations
    is_suspicious, reason = monitor._check_boundary_violations(tx)
    
    # Property assertion
    if function_name not in expected_functions:
        assert is_suspicious is True, \
            f"Function '{function_name}' not in expected_functions should be flagged as suspicious"
        assert reason != "", \
            f"Reason should be non-empty for unknown function '{function_name}'"
        assert function_name in reason or "Unknown function" in reason, \
            f"Reason should reference the unknown function: {reason}"
    else:
        # If function is in expected_functions, it should not be flagged for this reason
        # (it might still be flagged for parameter violations, but not for unknown function)
        if is_suspicious:
            # If flagged, it should be for a different reason (not unknown function)
            assert "Unknown function" not in reason, \
                f"Known function '{function_name}' should not be flagged as unknown"


@settings(max_examples=100, deadline=None)
@given(
    param_value=st.integers(min_value=-1000000, max_value=1000000),
    max_param_value=st.integers(min_value=0, max_value=100000)
)
def test_property_10_sentinel_flags_boundary_violations(
    param_value: int,
    max_param_value: int
):
    """
    Property 10: SentinelMonitor flags parameter boundary violations as SUSPICIOUS
    
    For any SentinelMonitor with any max_param_value, and any transaction where
    at least one numeric parameter exceeds max_param_value, _check_boundary_violations
    must return (True, reason) where reason references the specific boundary value exceeded.
    
    **Validates: Requirements 6.4**
    """
    # Create audit bounds with the max_param_value
    audit_bounds = AuditBounds(
        max_param_value=max_param_value,
        expected_functions=["test_function"],
        risk_score=50
    )
    
    # Create SentinelMonitor
    monitor = SentinelMonitor(
        contract_id="CTEST123",
        contract_hash="test_hash",
        audit_bounds=audit_bounds
    )
    
    # Create a transaction with a numeric parameter
    tx = {
        "function": "test_function",
        "parameters": {
            "amount": param_value
        }
    }
    
    # Check boundary violations
    is_suspicious, reason = monitor._check_boundary_violations(tx)
    
    # Property assertion
    if param_value > max_param_value:
        assert is_suspicious is True, \
            f"Parameter value {param_value} exceeding max {max_param_value} should be flagged"
        assert reason != "", \
            f"Reason should be non-empty for boundary violation"
        assert str(max_param_value) in reason, \
            f"Reason should reference the boundary value {max_param_value}: {reason}"
        assert "amount" in reason or "Parameter" in reason, \
            f"Reason should reference the parameter: {reason}"
    else:
        # If param_value <= max_param_value, should not be flagged for boundary violation
        if is_suspicious:
            # If flagged, it should be for a different reason (not boundary violation)
            assert "exceeds" not in reason.lower(), \
                f"Parameter within bounds should not be flagged for exceeding: {reason}"


@settings(max_examples=100, deadline=None)
@given(
    status=st.sampled_from(["NORMAL", "SUSPICIOUS", "FLAGGED"])
)
def test_property_11_feed_entry_event_matches_status(status: str):
    """
    Property 11: SentinelFeedEntry event field matches status
    
    For any SentinelFeedEntry, the event field must equal "NORMAL_TX" when
    status="NORMAL", "SUSPICIOUS_TX" when status="SUSPICIOUS", and "FLAGGED_TX"
    when status="FLAGGED".
    
    **Validates: Requirements 14.4**
    """
    # Create audit bounds
    audit_bounds = AuditBounds(
        max_param_value=10000,
        expected_functions=["test_function"],
        risk_score=50
    )
    
    # Create SentinelMonitor
    monitor = SentinelMonitor(
        contract_id="CTEST123",
        contract_hash="test_hash",
        audit_bounds=audit_bounds
    )
    
    # Create a transaction
    tx = {
        "function": "test_function",
        "parameters": {},
        "created_at": "2025-04-30T14:23:11Z"
    }
    
    # Build feed entry with the given status
    entry = monitor._build_feed_entry(tx, status, "test reason")
    
    # Property assertion: event must match status
    expected_event_map = {
        "NORMAL": "NORMAL_TX",
        "SUSPICIOUS": "SUSPICIOUS_TX",
        "FLAGGED": "FLAGGED_TX"
    }
    expected_event = expected_event_map[status]
    
    assert entry.event == expected_event, \
        f"Status '{status}' should map to event '{expected_event}', got '{entry.event}'"


@settings(max_examples=100, deadline=None)
@given(
    dt=st.datetimes(
        min_value=datetime(1970, 1, 1),
        max_value=datetime(2100, 12, 31),
        timezones=st.just(timezone.utc)
    )
)
def test_property_12_feed_entry_timestamp_iso8601_utc(dt: datetime):
    """
    Property 12: SentinelFeedEntry timestamp is valid ISO-8601 UTC
    
    For any SentinelFeedEntry produced by _build_feed_entry, the timestamp field
    must be parseable as a valid ISO-8601 datetime with UTC timezone (ending in Z
    or +00:00) and represent a time no earlier than the Unix epoch.
    
    **Validates: Requirements 14.5**
    """
    # Create audit bounds
    audit_bounds = AuditBounds(
        max_param_value=10000,
        expected_functions=["test_function"],
        risk_score=50
    )
    
    # Create SentinelMonitor
    monitor = SentinelMonitor(
        contract_id="CTEST123",
        contract_hash="test_hash",
        audit_bounds=audit_bounds
    )
    
    # Format datetime as ISO-8601 UTC
    timestamp_str = dt.isoformat().replace("+00:00", "Z")
    
    # Create a transaction with the timestamp
    tx = {
        "function": "test_function",
        "parameters": {},
        "created_at": timestamp_str
    }
    
    # Build feed entry
    entry = monitor._build_feed_entry(tx, "NORMAL", "")
    
    # Property assertion: timestamp must be valid ISO-8601 UTC
    assert entry.timestamp != "", \
        "Timestamp should not be empty"
    
    # Parse the timestamp to verify it's valid ISO-8601
    try:
        parsed_dt = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
    except ValueError as e:
        pytest.fail(f"Timestamp '{entry.timestamp}' is not valid ISO-8601: {e}")
    
    # Verify it's UTC (has timezone info)
    assert parsed_dt.tzinfo is not None, \
        f"Timestamp '{entry.timestamp}' should have timezone info"
    
    # Verify it's not earlier than Unix epoch
    unix_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert parsed_dt >= unix_epoch, \
        f"Timestamp '{entry.timestamp}' should not be earlier than Unix epoch"
    
    # Verify it ends with Z or +00:00 (UTC indicator)
    assert entry.timestamp.endswith("Z") or "+00:00" in entry.timestamp, \
        f"Timestamp '{entry.timestamp}' should end with Z or +00:00 to indicate UTC"


@settings(max_examples=100, deadline=None)
@given(
    status=st.sampled_from(["NORMAL", "SUSPICIOUS", "FLAGGED"]),
    reason_text=st.text(min_size=0, max_size=100)
)
def test_property_13_flagged_reason_non_empty_normal_reason_empty(
    status: str,
    reason_text: str
):
    """
    Property 13: FLAGGED entries always have a non-empty reason; NORMAL entries have empty reason
    
    For any SentinelFeedEntry where status="FLAGGED", reason must be a non-empty string.
    For any entry where status="NORMAL", reason must be an empty string or absent.
    
    **Validates: Requirements 14.2, 14.3**
    """
    # Create audit bounds
    audit_bounds = AuditBounds(
        max_param_value=10000,
        expected_functions=["test_function"],
        risk_score=50
    )
    
    # Create SentinelMonitor
    monitor = SentinelMonitor(
        contract_id="CTEST123",
        contract_hash="test_hash",
        audit_bounds=audit_bounds
    )
    
    # Create a transaction
    tx = {
        "function": "test_function",
        "parameters": {},
        "created_at": "2025-04-30T14:23:11Z"
    }
    
    # Determine the reason based on status
    # For FLAGGED, we should always provide a non-empty reason
    # For NORMAL, we should always provide an empty reason
    if status == "FLAGGED":
        # Ensure reason is non-empty for FLAGGED
        reason = reason_text if reason_text else "Flagged by system"
    elif status == "NORMAL":
        # Ensure reason is empty for NORMAL
        reason = ""
    else:
        # SUSPICIOUS can have either
        reason = reason_text
    
    # Build feed entry
    entry = monitor._build_feed_entry(tx, status, reason)
    
    # Property assertions
    if status == "FLAGGED":
        assert entry.reason != "", \
            f"FLAGGED entry must have non-empty reason, got: '{entry.reason}'"
    elif status == "NORMAL":
        assert entry.reason == "", \
            f"NORMAL entry must have empty reason, got: '{entry.reason}'"
    # SUSPICIOUS can have either empty or non-empty reason


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

