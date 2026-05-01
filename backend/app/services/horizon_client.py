"""
Horizon API client for querying Stellar transaction logs.
"""

import httpx
import asyncio
import logging
from typing import Optional, List, Tuple, Dict, Any
from app.models.schemas import DynamicLogEntry

logger = logging.getLogger(__name__)

HORIZON_URL_DEFAULT = "https://horizon-testnet.stellar.org"
MAX_RETRIES = 3
RETRY_DELAY = 2.0  # seconds


class HorizonClient:
    """
    Queries the Stellar Horizon REST API to retrieve transaction logs.
    """

    def __init__(self, public_key: str, horizon_url: str = HORIZON_URL_DEFAULT):
        """
        Initialize the Horizon client.

        Args:
            public_key: Stellar account public key for queries
            horizon_url: Horizon API base URL (default: testnet)
        """
        self.public_key = public_key
        self.horizon_url = horizon_url

    async def collect_logs(
        self,
        fuzz_results: List,  # List[FuzzResult]
        contract_hash: str,
    ) -> Tuple[List[DynamicLogEntry], str]:
        """
        For each FuzzResult, queries Horizon API for transaction details.
        Associates each log entry with its originating FuzzResult by transaction hash.
        Returns entries sorted by timestamp ascending.

        Args:
            fuzz_results: List of FuzzResult objects from fuzzing execution
            contract_hash: SHA-256 hash of the contract code

        Returns:
            Tuple of (log_entries_sorted_by_timestamp, status_code)
            status_code: "OK" | "HORIZON_UNAVAILABLE"
        """
        log_entries: List[DynamicLogEntry] = []
        status_code = "OK"

        # Query Horizon for recent transactions
        url = f"{self.horizon_url}/accounts/{self.public_key}/transactions?order=desc&limit=5"
        tx_data_list = await self._fetch_with_retry(url)

        if tx_data_list is None:
            logger.error(f"Horizon API unavailable for contract {contract_hash}")
            status_code = "HORIZON_UNAVAILABLE"
            # Return partial results without log enrichment
            for fuzz_result in fuzz_results:
                entry = self._parse_transaction({}, fuzz_result)
                log_entries.append(entry)
        else:
            # Parse transactions and associate with fuzz results
            # Build a map of transaction hash -> tx_data for quick lookup
            tx_map = {}
            if isinstance(tx_data_list, dict) and "_embedded" in tx_data_list:
                records = tx_data_list.get("_embedded", {}).get("records", [])
                for tx in records:
                    tx_hash = tx.get("hash", "")
                    if tx_hash:
                        tx_map[tx_hash] = tx

            # Associate each fuzz result with its transaction data
            for fuzz_result in fuzz_results:
                tx_hash = fuzz_result.transaction_hash
                tx_data = tx_map.get(tx_hash, {})
                entry = self._parse_transaction(tx_data, fuzz_result)
                log_entries.append(entry)

        # Sort entries by timestamp ascending
        log_entries.sort(key=lambda e: e.timestamp)

        return log_entries, status_code

    async def _fetch_with_retry(self, url: str) -> Optional[Dict[str, Any]]:
        """
        GET {url} with up to MAX_RETRIES retries and RETRY_DELAY between attempts.
        Returns parsed JSON on success, None after all retries exhausted.

        Args:
            url: Full URL to fetch

        Returns:
            Parsed JSON dict on success, None on failure
        """
        async with httpx.AsyncClient() as client:
            for attempt in range(MAX_RETRIES):
                try:
                    response = await client.get(url, timeout=10.0)
                    if response.status_code == 200:
                        return response.json()
                    else:
                        logger.warning(
                            f"Horizon API returned {response.status_code} on attempt {attempt + 1}/{MAX_RETRIES}"
                        )
                except httpx.HTTPError as e:
                    logger.warning(
                        f"Horizon API request failed on attempt {attempt + 1}/{MAX_RETRIES}: {e}"
                    )

                # Wait before retry (except on last attempt)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY)

        # All retries exhausted
        return None

    def _parse_transaction(
        self, tx_data: Dict[str, Any], fuzz_result
    ) -> DynamicLogEntry:
        """
        Extracts transaction details into a DynamicLogEntry.

        Args:
            tx_data: Horizon transaction response dict (may be empty)
            fuzz_result: FuzzResult object with function and parameter info

        Returns:
            DynamicLogEntry with extracted fields
        """
        # Extract from Horizon response if available
        transaction_hash = tx_data.get("hash", fuzz_result.transaction_hash or "")
        timestamp = tx_data.get("created_at", "")

        # If no timestamp from Horizon, use current time
        if not timestamp:
            from datetime import datetime, timezone
            timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Extract from fuzz_result
        function_called = fuzz_result.function_name
        parameters = fuzz_result.parameters
        result = fuzz_result.result
        error = fuzz_result.error

        # Initialize with default classification (will be updated by Groq)
        return DynamicLogEntry(
            timestamp=timestamp,
            transaction_hash=transaction_hash,
            function_called=function_called,
            parameters=parameters,
            result=result,
            error=error,
            anomaly=False,
            severity="NONE",
            status="NORMAL",
            reason=""
        )

    async def poll_contract_transactions(
        self,
        contract_id: str,
        cursor: str = "now",
    ) -> List[Dict[str, Any]]:
        """
        Used by SentinelMonitor. Queries Horizon for contract transactions.

        Args:
            contract_id: Stellar contract address (C... format)
            cursor: Horizon cursor for pagination (default: "now")

        Returns:
            List of raw transaction dicts, [] on failure
        """
        url = f"{self.horizon_url}/contracts/{contract_id}/transactions?cursor={cursor}&order=asc"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=10.0)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, dict) and "_embedded" in data:
                        return data.get("_embedded", {}).get("records", [])
        except Exception as e:
            logger.error(f"Failed to poll contract transactions for {contract_id}: {e}")

        return []
