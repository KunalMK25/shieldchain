"""
Property-based tests for GroqClassifier service.

Feature: dynamic-analysis-sentinel-audit
Property 5: Groq classification status mapping is correct for any (anomaly, severity) pair

**Validates: Requirements 4.3, 4.4**
"""

import pytest
from hypothesis import given, settings, strategies as st

from app.services.groq_classifier import GroqClassifier


@settings(max_examples=100, deadline=None)
@given(
    anomaly=st.booleans(),
    severity=st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])
)
def test_property_5_groq_status_mapping(anomaly: bool, severity: str):
    """
    Property 5: Groq classification status mapping is correct for any (anomaly, severity) pair
    
    For any anomaly=True with severity in {CRITICAL, HIGH, MEDIUM, LOW},
    _determine_status must return "FLAGGED" for CRITICAL/HIGH and "SUSPICIOUS" for
    MEDIUM/LOW; for any anomaly=False, must return "NORMAL".
    
    **Validates: Requirements 4.3, 4.4**
    """
    # Create a classifier instance (API key not needed for pure function test)
    classifier = GroqClassifier(api_key="test_key")
    
    # Call the pure function
    status = classifier._determine_status(anomaly, severity)
    
    # Property assertions based on the STATUS_MAP specification
    if anomaly:
        if severity in ["CRITICAL", "HIGH"]:
            assert status == "FLAGGED", \
                f"anomaly=True with severity={severity} should return FLAGGED, got {status}"
        elif severity in ["MEDIUM", "LOW"]:
            assert status == "SUSPICIOUS", \
                f"anomaly=True with severity={severity} should return SUSPICIOUS, got {status}"
        else:
            # NONE with anomaly=True is an edge case - should still map to something valid
            assert status in ["NORMAL", "SUSPICIOUS", "FLAGGED"], \
                f"anomaly=True with severity={severity} returned invalid status: {status}"
    else:
        # anomaly=False should always return NORMAL regardless of severity
        assert status == "NORMAL", \
            f"anomaly=False with severity={severity} should return NORMAL, got {status}"


@settings(max_examples=100, deadline=None)
@given(
    severity=st.text(min_size=1, max_size=20)
)
def test_property_5_unknown_severity_defaults_to_normal(severity: str):
    """
    Property 5 (edge case): Unknown severity values default to NORMAL
    
    For any severity string not in the known set, _determine_status should
    gracefully default to "NORMAL" rather than raising an exception.
    """
    # Filter out known severities to test unknown ones
    known_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
    if severity.upper() in known_severities:
        return  # Skip known severities
    
    classifier = GroqClassifier(api_key="test_key")
    
    # Test with anomaly=False (should always be NORMAL)
    status_false = classifier._determine_status(False, severity)
    assert status_false == "NORMAL", \
        f"Unknown severity with anomaly=False should default to NORMAL, got {status_false}"
    
    # Test with anomaly=True (should also default to NORMAL for unknown severity)
    status_true = classifier._determine_status(True, severity)
    assert status_true == "NORMAL", \
        f"Unknown severity with anomaly=True should default to NORMAL, got {status_true}"


@settings(max_examples=100, deadline=None)
@given(
    anomaly=st.booleans(),
    severity=st.sampled_from(["critical", "high", "medium", "low", "none"])  # lowercase
)
def test_property_5_case_insensitive_severity(anomaly: bool, severity: str):
    """
    Property 5 (case handling): Severity matching should be case-insensitive
    
    The _determine_status function should handle lowercase severity values
    correctly by normalizing them to uppercase.
    """
    classifier = GroqClassifier(api_key="test_key")
    
    # Call with lowercase severity
    status = classifier._determine_status(anomaly, severity)
    
    # Should produce the same result as uppercase
    severity_upper = severity.upper()
    expected_status = classifier._determine_status(anomaly, severity_upper)
    
    assert status == expected_status, \
        f"Case-insensitive handling failed: {severity} -> {status}, {severity_upper} -> {expected_status}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
