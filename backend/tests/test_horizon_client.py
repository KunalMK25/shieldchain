"""
Unit tests for HorizonClient service.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.services.horizon_client import HorizonClient, RETRY_DELAY, MAX_RETRIES
from dataclasses import dataclass
from typing import Dict, Any, Optional
import httpx


@dataclass
class MockFuzzResult:
    """Mock FuzzResult for testing."""
    function_name: str
    parameters: Dict[str, Any]
    strategy: str
    transaction_hash: str
    result: Optional[str]
    error: Optional[str]
    timed_out: bool


@pytest.mark.asyncio
async def test_retry_on_non_200():
    """
    Test that HorizonClient retries on non-200 HTTP responses.
    Mock HTTP 500 three times, verify 3 retry attempts.
    
    **Validates: Requirements 3.3**
    """
    client = HorizonClient(public_key="GTEST")
    
    # Mock httpx.AsyncClient to return 500 status
    mock_response = MagicMock()
    mock_response.status_code = 500
    
    with patch('httpx.AsyncClient') as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client
        
        # Mock asyncio.sleep to avoid actual delays
        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await client._fetch_with_retry("https://test.url")
            
            # Verify result is None after all retries
            assert result is None
            
            # Verify get was called MAX_RETRIES times
            assert mock_client.get.call_count == MAX_RETRIES
            
            # Verify sleep was called MAX_RETRIES - 1 times (no sleep after last attempt)
            assert mock_sleep.call_count == MAX_RETRIES - 1


@pytest.mark.asyncio
async def test_horizon_unavailable_after_retries():
    """
    Test that HorizonClient returns HORIZON_UNAVAILABLE status after all retries fail.
    Mock always-failing HTTP, verify "HORIZON_UNAVAILABLE" status.
    
    **Validates: Requirements 3.4**
    """
    client = HorizonClient(public_key="GTEST")
    
    # Create mock fuzz results
    fuzz_results = [
        MockFuzzResult(
            function_name="test_func",
            parameters={"amount": 100},
            strategy="test",
            transaction_hash="hash123",
            result="success",
            error=None,
            timed_out=False
        )
    ]
    
    # Mock _fetch_with_retry to always return None (simulating failure)
    with patch.object(client, '_fetch_with_retry', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = None
        
        entries, status = await client.collect_logs(fuzz_results, "test_hash")
        
        # Verify status is HORIZON_UNAVAILABLE
        assert status == "HORIZON_UNAVAILABLE"
        
        # Verify we still get entries (without Horizon enrichment)
        assert len(entries) == 1
        assert entries[0].function_called == "test_func"


@pytest.mark.asyncio
async def test_retry_delay():
    """
    Test that HorizonClient waits RETRY_DELAY seconds between retries.
    Verify 2-second delays between retries.
    
    **Validates: Requirements 3.3**
    """
    client = HorizonClient(public_key="GTEST")
    
    # Mock httpx.AsyncClient to raise HTTPError
    with patch('httpx.AsyncClient') as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.get = AsyncMock(side_effect=httpx.HTTPError("Connection failed"))
        mock_client_class.return_value = mock_client
        
        # Mock asyncio.sleep to track delays
        with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
            result = await client._fetch_with_retry("https://test.url")
            
            # Verify result is None
            assert result is None
            
            # Verify sleep was called with RETRY_DELAY
            assert mock_sleep.call_count == MAX_RETRIES - 1
            for call in mock_sleep.call_args_list:
                assert call[0][0] == RETRY_DELAY, \
                    f"Expected delay of {RETRY_DELAY}s, got {call[0][0]}s"


@pytest.mark.asyncio
async def test_collect_logs_success():
    """
    Test successful log collection with valid Horizon response.
    """
    client = HorizonClient(public_key="GTEST")
    
    # Create mock fuzz results
    fuzz_results = [
        MockFuzzResult(
            function_name="transfer",
            parameters={"amount": 100},
            strategy="happy_path",
            transaction_hash="abc123",
            result="success",
            error=None,
            timed_out=False
        )
    ]
    
    # Mock Horizon API response
    mock_horizon_response = {
        "_embedded": {
            "records": [
                {
                    "hash": "abc123",
                    "created_at": "2025-04-30T14:23:11Z",
                    "envelope_xdr": "mock_xdr"
                }
            ]
        }
    }
    
    with patch.object(client, '_fetch_with_retry', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = mock_horizon_response
        
        entries, status = await client.collect_logs(fuzz_results, "test_hash")
        
        # Verify status is OK
        assert status == "OK"
        
        # Verify entries are populated correctly
        assert len(entries) == 1
        assert entries[0].transaction_hash == "abc123"
        assert entries[0].timestamp == "2025-04-30T14:23:11Z"
        assert entries[0].function_called == "transfer"
        assert entries[0].parameters == {"amount": 100}


@pytest.mark.asyncio
async def test_poll_contract_transactions_success():
    """
    Test successful polling of contract transactions.
    """
    client = HorizonClient(public_key="GTEST")
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "_embedded": {
            "records": [
                {"hash": "tx1", "created_at": "2025-04-30T14:23:11Z"},
                {"hash": "tx2", "created_at": "2025-04-30T14:23:21Z"}
            ]
        }
    }
    
    with patch('httpx.AsyncClient') as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value = mock_client
        
        transactions = await client.poll_contract_transactions("CTEST123", "now")
        
        # Verify transactions are returned
        assert len(transactions) == 2
        assert transactions[0]["hash"] == "tx1"
        assert transactions[1]["hash"] == "tx2"


@pytest.mark.asyncio
async def test_poll_contract_transactions_failure():
    """
    Test that poll_contract_transactions returns empty list on failure.
    """
    client = HorizonClient(public_key="GTEST")
    
    with patch('httpx.AsyncClient') as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.get = AsyncMock(side_effect=httpx.HTTPError("Connection failed"))
        mock_client_class.return_value = mock_client
        
        transactions = await client.poll_contract_transactions("CTEST123", "now")
        
        # Verify empty list is returned
        assert transactions == []
