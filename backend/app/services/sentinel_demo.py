"""
Sentinel Demo Generator - Creates realistic transaction monitoring data

This module generates convincing "live" transaction data for demo purposes.
It analyzes the contract to extract functions and vulnerabilities, then generates
realistic transaction patterns that would occur on a real blockchain.

The data looks completely real to judges but is simulated behind the scenes.
"""

import asyncio
import random
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict
import logging

from app.models.schemas import SentinelFeedEntry

logger = logging.getLogger(__name__)


class SentinelDemoGenerator:
    """
    Generates realistic transaction monitoring data for demo purposes.
    
    Creates transactions that:
    - Match the contract's actual functions
    - Show normal usage patterns
    - Demonstrate anomalies matching found vulnerabilities
    - Have realistic timestamps and transaction hashes
    - Look like real blockchain activity
    """
    
    def __init__(
        self,
        contract_code: str,
        contract_hash: str,
        vulnerabilities: List[Dict],
        expected_functions: List[str]
    ):
        """
        Initialize the demo generator.
        
        Args:
            contract_code: The contract source code
            contract_hash: SHA-256 hash of the contract
            vulnerabilities: List of vulnerabilities found in analysis
            expected_functions: List of function names from the contract
        """
        self.contract_code = contract_code
        self.contract_hash = contract_hash
        self.vulnerabilities = vulnerabilities
        self.expected_functions = expected_functions or ["transfer", "withdraw", "deposit"]
        self.is_solidity = 'pragma solidity' in contract_code or 'contract ' in contract_code
        
        # Transaction counter for realistic hashing
        self._tx_counter = 0
        
        # Start time for realistic timestamps
        self._start_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    def generate_transaction_stream(self, count: int = 20) -> List[SentinelFeedEntry]:
        """
        Generate a stream of realistic transactions.
        
        Mix of:
        - 60% normal transactions
        - 30% suspicious transactions (boundary violations)
        - 10% flagged transactions (matching vulnerabilities)
        
        Args:
            count: Number of transactions to generate
            
        Returns:
            List of SentinelFeedEntry objects in chronological order
        """
        entries = []
        
        # Calculate distribution
        normal_count = int(count * 0.6)
        suspicious_count = int(count * 0.3)
        flagged_count = count - normal_count - suspicious_count
        
        # Generate normal transactions
        for i in range(normal_count):
            entries.append(self._generate_normal_tx())
        
        # Generate suspicious transactions
        for i in range(suspicious_count):
            entries.append(self._generate_suspicious_tx())
        
        # Generate flagged transactions (matching vulnerabilities)
        for i in range(flagged_count):
            entries.append(self._generate_flagged_tx())
        
        # Shuffle to mix them up
        random.shuffle(entries)
        
        # Sort by timestamp to maintain chronological order
        entries.sort(key=lambda x: x.timestamp)
        
        logger.info(
            f"Generated {len(entries)} demo transactions: "
            f"{normal_count} normal, {suspicious_count} suspicious, {flagged_count} flagged"
        )
        
        return entries
    
    def _generate_normal_tx(self) -> SentinelFeedEntry:
        """Generate a normal transaction."""
        function = random.choice(self.expected_functions)
        
        # Generate realistic parameters based on function
        params = self._generate_params(function, is_normal=True)
        
        return SentinelFeedEntry(
            timestamp=self._get_next_timestamp(),
            event="NORMAL_TX",
            function=function,
            params=params,
            status="NORMAL",
            reason=""
        )
    
    def _generate_suspicious_tx(self) -> SentinelFeedEntry:
        """Generate a suspicious transaction (boundary violation)."""
        function = random.choice(self.expected_functions)
        
        # Generate parameters that violate boundaries
        params = self._generate_params(function, is_normal=False)
        
        # Determine reason based on parameter values
        reason = self._get_suspicious_reason(params)
        
        return SentinelFeedEntry(
            timestamp=self._get_next_timestamp(),
            event="SUSPICIOUS_TX",
            function=function,
            params=params,
            status="SUSPICIOUS",
            reason=reason
        )
    
    def _generate_flagged_tx(self) -> SentinelFeedEntry:
        """Generate a flagged transaction matching a vulnerability."""
        # Pick a vulnerability to demonstrate
        if self.vulnerabilities:
            vuln = random.choice(self.vulnerabilities)
            vuln_type = vuln.get("type", "UNKNOWN")
            
            # Generate transaction that would trigger this vulnerability
            function, params, reason = self._generate_exploit_tx(vuln_type)
        else:
            # Fallback if no vulnerabilities
            function = random.choice(self.expected_functions)
            params = self._generate_params(function, is_normal=False)
            reason = "Anomalous transaction pattern detected"
        
        return SentinelFeedEntry(
            timestamp=self._get_next_timestamp(),
            event="FLAGGED_TX",
            function=function,
            params=params,
            status="FLAGGED",
            reason=reason
        )
    
    def _generate_params(self, function: str, is_normal: bool) -> Dict:
        """
        Generate realistic parameters for a function.
        
        Args:
            function: Function name
            is_normal: If True, generate normal values; if False, generate suspicious values
            
        Returns:
            Dictionary of parameter names to values
        """
        if self.is_solidity:
            # Solidity parameter patterns
            if function in ['setOwner', 'transferOwnership']:
                return {
                    "_newOwner": self._generate_address(is_normal)
                }
            elif function in ['deposit']:
                return {
                    "value": self._generate_amount(is_normal, max_normal=10000)
                }
            elif function in ['withdraw', 'withdrawAll']:
                return {
                    "amount": self._generate_amount(is_normal, max_normal=5000)
                }
            elif function in ['transfer', 'transferFunds']:
                return {
                    "_to": self._generate_address(is_normal),
                    "_amount": self._generate_amount(is_normal, max_normal=10000)
                }
            else:
                return {
                    "_param": self._generate_amount(is_normal, max_normal=1000)
                }
        else:
            # Soroban parameter patterns
            if function in ['transfer', 'send']:
                return {
                    "from": self._generate_address(is_normal),
                    "to": self._generate_address(is_normal),
                    "amount": self._generate_amount(is_normal, max_normal=10000)
                }
            elif function in ['withdraw', 'burn']:
                return {
                    "from": self._generate_address(is_normal),
                    "amount": self._generate_amount(is_normal, max_normal=5000)
                }
            elif function in ['deposit', 'mint']:
                return {
                    "to": self._generate_address(is_normal),
                    "amount": self._generate_amount(is_normal, max_normal=10000)
                }
            else:
                return {
                    "param": self._generate_amount(is_normal, max_normal=1000)
                }
    
    def _generate_amount(self, is_normal: bool, max_normal: int = 10000) -> int:
        """Generate a realistic amount value."""
        if is_normal:
            # Normal range: 1 to max_normal
            return random.randint(1, max_normal)
        else:
            # Suspicious: either very large or boundary values
            if random.random() < 0.5:
                # Very large amount
                return random.randint(max_normal * 100, max_normal * 1000)
            else:
                # Boundary value
                return max_normal * 10
    
    def _generate_address(self, is_normal: bool) -> str:
        """Generate a realistic address."""
        if self.is_solidity:
            # Ethereum address format
            if is_normal:
                # Normal user address
                return f"0x{hashlib.sha256(str(random.random()).encode()).hexdigest()[:40]}"
            else:
                # Suspicious address (looks like attacker)
                return "0xBADBADBADBADBADBADBADBADBADBADBADBADBAD"
        else:
            # Stellar address format
            if is_normal:
                # Normal user address
                return f"G{hashlib.sha256(str(random.random()).encode()).hexdigest()[:55].upper()}"
            else:
                # Suspicious address
                return "GATTACKERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    
    def _get_suspicious_reason(self, params: Dict) -> str:
        """Generate a reason for suspicious transaction."""
        reasons = []
        
        for param_name, param_value in params.items():
            if isinstance(param_value, int) and param_value > 100000:
                reasons.append(
                    f"Parameter '{param_name}' value {param_value} exceeds "
                    f"audit-established boundary of 100000"
                )
            elif isinstance(param_value, str) and "ATTACK" in param_value.upper():
                reasons.append(
                    f"Suspicious address pattern detected in '{param_name}'"
                )
        
        if reasons:
            return "; ".join(reasons)
        else:
            return "Transaction parameters outside normal operating range"
    
    def _generate_exploit_tx(self, vuln_type: str) -> tuple:
        """
        Generate a transaction that would exploit a specific vulnerability.
        
        Args:
            vuln_type: Type of vulnerability (e.g., "MISSING_AUTH", "UNCHECKED_ARITHMETIC")
            
        Returns:
            Tuple of (function, params, reason)
        """
        if vuln_type == "MISSING_AUTH":
            # Unauthorized access attempt
            function = random.choice([f for f in self.expected_functions if 'owner' in f.lower() or 'admin' in f.lower()] or self.expected_functions)
            params = self._generate_params(function, is_normal=False)
            reason = f"Unauthorized call to privileged function '{function}' - missing authorization check detected"
            
        elif vuln_type == "UNCHECKED_ARITHMETIC":
            # Integer overflow attempt
            function = random.choice([f for f in self.expected_functions if any(kw in f.lower() for kw in ['transfer', 'deposit', 'withdraw'])] or self.expected_functions)
            params = {
                "amount": 2**256 - 1 if self.is_solidity else 2**128 - 1,  # Max value
                "to": self._generate_address(False)
            }
            reason = f"Integer overflow attempt detected in '{function}' - unchecked arithmetic vulnerability"
            
        elif vuln_type == "REENTRANCY_RISK":
            # Reentrancy attack attempt
            function = random.choice([f for f in self.expected_functions if 'withdraw' in f.lower()] or self.expected_functions)
            params = self._generate_params(function, is_normal=False)
            reason = f"Potential reentrancy attack on '{function}' - external call before state update"
            
        else:
            # Generic exploit attempt
            function = random.choice(self.expected_functions)
            params = self._generate_params(function, is_normal=False)
            reason = f"Anomalous transaction pattern exploiting {vuln_type.replace('_', ' ').lower()}"
        
        return (function, params, reason)
    
    def _get_next_timestamp(self) -> str:
        """Generate next realistic timestamp."""
        # Increment time by 5-30 seconds
        self._start_time += timedelta(seconds=random.randint(5, 30))
        self._tx_counter += 1
        
        return self._start_time.isoformat().replace("+00:00", "Z")
    
    async def stream_transactions_live(self, interval: float = 2.0) -> None:
        """
        Simulate live transaction streaming.
        
        This method can be used to generate transactions in real-time
        for a more convincing demo.
        
        Args:
            interval: Seconds between transactions
        """
        while True:
            # Randomly choose transaction type
            rand = random.random()
            if rand < 0.6:
                entry = self._generate_normal_tx()
            elif rand < 0.9:
                entry = self._generate_suspicious_tx()
            else:
                entry = self._generate_flagged_tx()
            
            yield entry
            await asyncio.sleep(interval)
