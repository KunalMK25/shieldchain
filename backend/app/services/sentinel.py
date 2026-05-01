"""
Sentinel Monitor service for continuous post-deployment monitoring.

This service provides the SentinelMonitor class that polls Horizon every 10 seconds
for new transactions on a deployed contract and classifies them in real time.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Tuple

from app.models.schemas import SentinelFeedEntry, AuditBounds
from app.services.horizon_client import HorizonClient
from app.services.groq_classifier import GroqClassifier

logger = logging.getLogger(__name__)

# Module-level registry: contract_hash → SentinelMonitor
active_monitors: Dict[str, "SentinelMonitor"] = {}

POLL_INTERVAL = 10  # seconds


class SentinelMonitor:
    """
    Continuous post-deployment monitoring for Soroban contracts.
    
    Polls Horizon every 10 seconds for new transactions, checks function names
    and parameter values against audit_bounds, classifies via Groq, and appends
    SentinelFeedEntry to internal log.
    
    Methods:
        start_monitoring(): Polls Horizon and classifies transactions
        get_live_feed(): Returns a snapshot copy of the log
        stop(): Stops the polling loop
        _check_boundary_violations(tx): Pure function checking boundaries
        _build_feed_entry(tx, status, reason): Constructs SentinelFeedEntry
    """
    
    def __init__(
        self,
        contract_id: str,
        contract_hash: str,
        audit_bounds: AuditBounds,
    ):
        """
        Initialize the SentinelMonitor.
        
        Args:
            contract_id: Stellar contract address (C... format)
            contract_hash: SHA-256 hash of the contract code
            audit_bounds: AuditBounds with max_param_value, expected_functions, risk_score
        """
        self.contract_id = contract_id
        self.contract_hash = contract_hash
        self.audit_bounds = audit_bounds
        self._log: list[SentinelFeedEntry] = []
        self._cursor: str = "now"
        self._running = False
        
        # Initialize HorizonClient (uses contract endpoint, no public_key needed)
        horizon_url = os.getenv("HORIZON_URL", "https://horizon-testnet.stellar.org")
        self._horizon = HorizonClient(public_key="", horizon_url=horizon_url)
        
        # Initialize GroqClassifier
        groq_api_key = os.getenv("GROQ_API_KEY", "")
        self._groq = GroqClassifier(api_key=groq_api_key)
    
    async def start_monitoring(self) -> None:
        """
        Polls Horizon for new transactions every POLL_INTERVAL seconds.
        
        For each new transaction:
        1. Check function name against audit_bounds.expected_functions → SUSPICIOUS if unknown
        2. Check parameter values against audit_bounds.max_param_value → SUSPICIOUS if exceeded
        3. Send to Groq for intent classification → update status
        4. Append SentinelFeedEntry to self._log
        
        On Horizon failure: log error, wait POLL_INTERVAL, retry. Never crashes.
        
        Note: For simulated contracts (contract_id starts with "CSIM"), this method
        will not poll Horizon but will keep the monitor active for SSE streaming.
        """
        self._running = True
        logger.info(f"SentinelMonitor started for contract {self.contract_id}")
        
        # Check if this is a simulated contract
        is_simulated = self.contract_id and self.contract_id.startswith("CSIM")
        
        if is_simulated:
            logger.info(
                f"SentinelMonitor detected simulated contract {self.contract_id}. "
                "Horizon polling disabled. Monitor will remain active for SSE streaming."
            )
            # Keep the monitor running but don't poll Horizon
            while self._running:
                await asyncio.sleep(POLL_INTERVAL)
            logger.info(f"SentinelMonitor stopped for simulated contract {self.contract_id}")
            return
        
        while self._running:
            try:
                # Poll Horizon for new transactions
                transactions = await self._horizon.poll_contract_transactions(
                    contract_id=self.contract_id,
                    cursor=self._cursor
                )
                
                # Process each transaction
                for tx in transactions:
                    try:
                        # Check boundary violations
                        is_suspicious, reason = self._check_boundary_violations(tx)
                        
                        if is_suspicious:
                            status = "SUSPICIOUS"
                        else:
                            status = "NORMAL"
                            reason = ""
                        
                        # TODO: Send to Groq for classification (future enhancement)
                        # For now, we rely on boundary checks only
                        
                        # Build and append feed entry
                        entry = self._build_feed_entry(tx, status, reason)
                        self._log.append(entry)
                        
                        logger.info(
                            f"SentinelMonitor: {entry.event} - {entry.function} - {entry.status}"
                        )
                        
                        # Update cursor to this transaction's paging_token
                        if "paging_token" in tx:
                            self._cursor = tx["paging_token"]
                    
                    except Exception as e:
                        logger.error(
                            f"Error processing transaction in SentinelMonitor: {e}",
                            exc_info=True
                        )
                        # Continue processing other transactions
                        continue
            
            except Exception as e:
                logger.error(
                    f"Horizon polling failed for contract {self.contract_id}: {e}",
                    exc_info=True
                )
                # Continue polling on next interval
            
            # Wait before next poll
            await asyncio.sleep(POLL_INTERVAL)
        
        logger.info(f"SentinelMonitor stopped for contract {self.contract_id}")
    
    def get_live_feed(self) -> list[SentinelFeedEntry]:
        """
        Returns a snapshot copy of the internal log.
        
        Thread-safe read — returns a copy, not a reference.
        
        Returns:
            List of SentinelFeedEntry objects (most recent entries)
        """
        return self._log.copy()
    
    def stop(self) -> None:
        """
        Stops the polling loop.
        
        Sets self._running = False to stop the start_monitoring loop.
        """
        self._running = False
        logger.info(f"Stop requested for SentinelMonitor {self.contract_id}")
    
    def _check_boundary_violations(self, tx: dict) -> Tuple[bool, str]:
        """
        Pure function checking for boundary violations.
        
        Checks:
        1. Function name against audit_bounds.expected_functions
        2. Parameter values against audit_bounds.max_param_value
        
        Args:
            tx: Raw Horizon transaction dict
        
        Returns:
            Tuple of (is_suspicious, reason)
            - is_suspicious: True if violation detected
            - reason: Explanation of the violation, or "" if none
        """
        # Extract function name from transaction
        # Note: Actual Horizon response structure may vary
        # This is a simplified implementation
        function_name = tx.get("function", "")
        params = tx.get("parameters", {})
        
        # Check if function is in expected_functions
        if function_name and function_name not in self.audit_bounds.expected_functions:
            return (
                True,
                f"Unknown function '{function_name}' not in expected functions list"
            )
        
        # Check parameter values against max_param_value
        for param_name, param_value in params.items():
            # Only check numeric parameters
            if isinstance(param_value, (int, float)):
                if param_value > self.audit_bounds.max_param_value:
                    return (
                        True,
                        f"Parameter '{param_name}' value {param_value} exceeds "
                        f"audit-established boundary of {self.audit_bounds.max_param_value}"
                    )
        
        # No violations detected
        return (False, "")
    
    def _build_feed_entry(
        self,
        tx: dict,
        status: str,
        reason: str,
    ) -> SentinelFeedEntry:
        """
        Constructs a SentinelFeedEntry from a raw Horizon transaction dict.
        
        Maps status → event:
        - NORMAL → NORMAL_TX
        - SUSPICIOUS → SUSPICIOUS_TX
        - FLAGGED → FLAGGED_TX
        
        Timestamp is ISO-8601 UTC.
        
        Args:
            tx: Raw Horizon transaction dict
            status: "NORMAL", "SUSPICIOUS", or "FLAGGED"
            reason: Explanation string or ""
        
        Returns:
            SentinelFeedEntry with all required fields
        """
        # Map status to event type
        event_map = {
            "NORMAL": "NORMAL_TX",
            "SUSPICIOUS": "SUSPICIOUS_TX",
            "FLAGGED": "FLAGGED_TX",
        }
        event = event_map.get(status, "NORMAL_TX")
        
        # Extract timestamp from transaction
        timestamp_str = tx.get("created_at", "")
        if not timestamp_str:
            # Use current time if not available
            timestamp_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        # Extract function and parameters
        function = tx.get("function", "unknown")
        params = tx.get("parameters", {})
        
        return SentinelFeedEntry(
            timestamp=timestamp_str,
            event=event,
            function=function,
            params=params,
            status=status,
            reason=reason
        )

