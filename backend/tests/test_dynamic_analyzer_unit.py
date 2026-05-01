"""
Unit tests for the DynamicAnalyzer service.

Tests specific scenarios like deployment failures, cleanup, missing env vars,
and timeouts.
"""

import pytest
import asyncio
import os
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

from app.services.dynamic_analyzer import (
    run_dynamic_analysis,
    _compute_risk_adjustment
)
from app.models.schemas import DynamicLogEntry


# ============================================================================
# Unit Tests - Updated for Simulation-Based Analysis
# ============================================================================
# Note: Many tests below are commented out as they test the old deployment-based
# approach. The new simulation-based approach doesn't use deployment, compilation,
# or file writing, so those tests are no longer applicable.

# @pytest.mark.asyncio
# async def test_deploy_failed_on_compile_error():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

# @pytest.mark.asyncio
# async def test_deploy_failed_on_deploy_error():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

# @pytest.mark.asyncio
# async def test_cleanup_on_success():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

# @pytest.mark.asyncio
# async def test_cleanup_on_failure():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

# @pytest.mark.asyncio
# async def test_missing_env_vars():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

# @pytest.mark.asyncio
# async def test_missing_stellar_public_key():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

@pytest.mark.asyncio
async def test_timeout_returns_partial():
    """
    **Validates: Requirements 13.5**

    Unit test: Verify dynamic_status="TIMEOUT" when pipeline exceeds 90 seconds.
    """
    # Arrange: Patch the simulation function to raise TimeoutError
    with patch('app.services.dynamic_analyzer._simulate_dynamic_execution') as mock_simulate:
        mock_simulate.side_effect = asyncio.TimeoutError("Operation timed out")
        
        # Act
        response = await run_dynamic_analysis(
            contract_code="valid rust code",
            contract_name="test contract",
            contract_hash="test_hash"
        )
        
        # Assert
        assert response.dynamic_status == "TIMEOUT", \
            "Expected TIMEOUT status when operation times out"
        assert response.contract_id is None
        assert response.dynamic_audit_log == []

# @pytest.mark.asyncio
# async def test_horizon_unavailable_status():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass

# def test_write_contract_file_creates_structure():
#     """Old test for deployment-based approach - no longer applicable"""
#     pass


def test_compute_risk_adjustment_critical():
    """
    Unit test: Verify CRITICAL anomalies add 5 points each.
    """
    # Arrange
    entries = [
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:00Z",
            transaction_hash="abc123",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,
            severity="CRITICAL",
            status="FLAGGED",
            reason="Critical issue"
        ),
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:01Z",
            transaction_hash="abc124",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,
            severity="CRITICAL",
            status="FLAGGED",
            reason="Another critical issue"
        )
    ]
    
    # Act
    adjustment = _compute_risk_adjustment(entries)
    
    # Assert
    assert adjustment == 10, "Expected 5 + 5 = 10 for two CRITICAL anomalies"


def test_compute_risk_adjustment_mixed():
    """
    Unit test: Verify mixed severity anomalies are weighted correctly.
    """
    # Arrange
    entries = [
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:00Z",
            transaction_hash="abc123",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,
            severity="CRITICAL",
            status="FLAGGED",
            reason="Critical"
        ),
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:01Z",
            transaction_hash="abc124",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,
            severity="HIGH",
            status="FLAGGED",
            reason="High"
        ),
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:02Z",
            transaction_hash="abc125",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,
            severity="MEDIUM",
            status="SUSPICIOUS",
            reason="Medium"
        ),
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:03Z",
            transaction_hash="abc126",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,
            severity="LOW",
            status="SUSPICIOUS",
            reason="Low"
        )
    ]
    
    # Act
    adjustment = _compute_risk_adjustment(entries)
    
    # Assert
    # CRITICAL=5, HIGH=3, MEDIUM=2, LOW=1 → 5+3+2+1=11
    assert adjustment == 11, "Expected 5+3+2+1=11 for mixed severities"


def test_compute_risk_adjustment_ignores_non_anomalies():
    """
    Unit test: Verify non-anomaly entries don't contribute to risk adjustment.
    """
    # Arrange
    entries = [
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:00Z",
            transaction_hash="abc123",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=False,  # Not an anomaly
            severity="CRITICAL",
            status="NORMAL",
            reason=""
        ),
        DynamicLogEntry(
            timestamp="2025-01-01T00:00:01Z",
            transaction_hash="abc124",
            function_called="test",
            parameters={},
            result=None,
            error=None,
            anomaly=True,  # Is an anomaly
            severity="HIGH",
            status="FLAGGED",
            reason="High severity"
        )
    ]
    
    # Act
    adjustment = _compute_risk_adjustment(entries)
    
    # Assert
    # Only the HIGH anomaly counts: 3
    assert adjustment == 3, "Expected 3 for one HIGH anomaly (CRITICAL ignored as non-anomaly)"


def test_compute_risk_adjustment_empty_list():
    """
    Unit test: Verify empty list returns 0.
    """
    # Arrange
    entries = []
    
    # Act
    adjustment = _compute_risk_adjustment(entries)
    
    # Assert
    assert adjustment == 0, "Expected 0 for empty list"
