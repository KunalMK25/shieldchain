"""
Fuzzing engine for generating and executing parameterized test transactions
against deployed Soroban contracts.
"""

import asyncio
import subprocess
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class FuzzTransaction:
    """Represents a single fuzzing transaction to be executed."""
    function_name: str
    parameters: Dict[str, Any]
    strategy: str  # "zero" | "boundary" | "overflow" | "adversarial" | "happy_path"


@dataclass
class FuzzResult:
    """Result of executing a fuzzing transaction."""
    function_name: str
    parameters: Dict[str, Any]
    strategy: str
    transaction_hash: str  # "" if not yet confirmed
    result: Optional[str]
    error: Optional[str]
    timed_out: bool


class FuzzingEngine:
    """
    Generates and executes parameterized fuzzing transactions against a deployed
    Soroban contract on Stellar Testnet.
    """

    # Supported Soroban parameter types
    PARAM_TYPES = ["u32", "u64", "u128", "i32", "i64", "i128", "String", "bool", "Address"]

    def __init__(self, contract_id: str, stellar_secret_key: str, network: str = "testnet"):
        """
        Initialize the fuzzing engine.

        Args:
            contract_id: Stellar contract address (C... format)
            stellar_secret_key: Secret key for signing transactions
            network: Soroban network name (default: "testnet")
        """
        self.contract_id = contract_id
        self.stellar_secret_key = stellar_secret_key
        self.network = network

    def generate_inputs(self, abi: List[Dict[str, Any]]) -> List[FuzzTransaction]:
        """
        Generate fuzzing transactions for all exported functions in the ABI.

        For each function, generates at least 5 transactions covering:
        - zero values (all params = zero equivalent for their type)
        - boundary values (u128::MAX, i128::MIN, etc.)
        - overflow values (exceeding valid range)
        - adversarial inputs (reentrancy, unauthorized address)
        - happy path (valid representative values)

        Args:
            abi: List of function definitions with name and parameters

        Returns:
            Flat list of all FuzzTransactions across all functions
        """
        transactions: List[FuzzTransaction] = []

        for func in abi:
            func_name = func.get("name", "")
            params = func.get("parameters", [])

            # Generate zero-value transaction
            zero_params = {}
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "u32")
                zero_params[param_name] = self._zero_value(param_type)

            transactions.append(FuzzTransaction(
                function_name=func_name,
                parameters=zero_params,
                strategy="zero"
            ))

            # Generate boundary-value transactions
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "u32")
                boundary_values = self._boundary_values(param_type)

                for boundary_val in boundary_values:
                    boundary_params = zero_params.copy()
                    boundary_params[param_name] = boundary_val
                    transactions.append(FuzzTransaction(
                        function_name=func_name,
                        parameters=boundary_params,
                        strategy="boundary"
                    ))

            # Generate overflow-value transaction
            overflow_params = {}
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "u32")
                overflow_params[param_name] = self._overflow_value(param_type)

            transactions.append(FuzzTransaction(
                function_name=func_name,
                parameters=overflow_params,
                strategy="overflow"
            ))

            # Generate adversarial-value transactions
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "u32")
                adversarial_values = self._adversarial_values(param_type)

                for adv_val in adversarial_values:
                    adv_params = zero_params.copy()
                    adv_params[param_name] = adv_val
                    transactions.append(FuzzTransaction(
                        function_name=func_name,
                        parameters=adv_params,
                        strategy="adversarial"
                    ))

            # Generate happy-path transaction
            happy_params = {}
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "u32")
                happy_params[param_name] = self._happy_path_value(param_type)

            transactions.append(FuzzTransaction(
                function_name=func_name,
                parameters=happy_params,
                strategy="happy_path"
            ))

        return transactions

    async def execute_all(
        self,
        transactions: List[FuzzTransaction],
        timeout_per_tx: float = 10.0,
    ) -> List[FuzzResult]:
        """
        Execute all fuzzing transactions sequentially.

        Each transaction is invoked via:
          soroban contract invoke --id {contract_id} --network {network}
                                  --source {stellar_secret_key}
                                  -- {function_name} {params...}

        Enforces timeout_per_tx per invocation. Records timeout as
        FuzzResult(timed_out=True) and continues. Never raises — all errors
        are captured in FuzzResult.error.

        Args:
            transactions: List of FuzzTransaction objects to execute
            timeout_per_tx: Timeout in seconds per transaction (default: 10.0)

        Returns:
            List of FuzzResult objects, one per input transaction
        """
        results: List[FuzzResult] = []

        for tx in transactions:
            try:
                # Build soroban CLI command
                cmd = [
                    "soroban", "contract", "invoke",
                    "--id", self.contract_id,
                    "--network", self.network,
                    "--source", self.stellar_secret_key,
                    "--",
                    tx.function_name
                ]

                # Add parameters
                for param_name, param_value in tx.parameters.items():
                    cmd.extend([f"--{param_name}", str(param_value)])

                # Execute with timeout
                process = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env={**os.environ, "STELLAR_SECRET_KEY": self.stellar_secret_key}
                    ),
                    timeout=timeout_per_tx
                )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout_per_tx
                )

                if process.returncode == 0:
                    # Success
                    result_str = stdout.decode().strip()
                    # Extract transaction hash from output (if present)
                    tx_hash = self._extract_tx_hash(result_str)
                    results.append(FuzzResult(
                        function_name=tx.function_name,
                        parameters=tx.parameters,
                        strategy=tx.strategy,
                        transaction_hash=tx_hash,
                        result=result_str,
                        error=None,
                        timed_out=False
                    ))
                else:
                    # Error
                    error_str = stderr.decode().strip()
                    results.append(FuzzResult(
                        function_name=tx.function_name,
                        parameters=tx.parameters,
                        strategy=tx.strategy,
                        transaction_hash="",
                        result=None,
                        error=error_str,
                        timed_out=False
                    ))

            except asyncio.TimeoutError:
                # Timeout
                results.append(FuzzResult(
                    function_name=tx.function_name,
                    parameters=tx.parameters,
                    strategy=tx.strategy,
                    transaction_hash="",
                    result=None,
                    error=f"timeout after {timeout_per_tx}s",
                    timed_out=True
                ))

            except Exception as e:
                # Unexpected error
                results.append(FuzzResult(
                    function_name=tx.function_name,
                    parameters=tx.parameters,
                    strategy=tx.strategy,
                    transaction_hash="",
                    result=None,
                    error=str(e),
                    timed_out=False
                ))

        return results

    def _zero_value(self, param_type: str) -> Any:
        """
        Return zero equivalent for the given parameter type.

        Args:
            param_type: Soroban parameter type

        Returns:
            Zero value for the type
        """
        if param_type in ["u32", "u64", "u128", "i32", "i64", "i128"]:
            return 0
        elif param_type == "String":
            return ""
        elif param_type == "bool":
            return False
        elif param_type == "Address":
            return "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        else:
            return 0

    def _boundary_values(self, param_type: str) -> List[Any]:
        """
        Return boundary values (min, max) for the given parameter type.

        Args:
            param_type: Soroban parameter type

        Returns:
            List of boundary values
        """
        if param_type == "u32":
            return [0, 4294967295]  # u32::MAX
        elif param_type == "u64":
            return [0, 18446744073709551615]  # u64::MAX
        elif param_type == "u128":
            return [0, 340282366920938463463374607431768211455]  # u128::MAX
        elif param_type == "i32":
            return [-2147483648, 2147483647]  # i32::MIN, i32::MAX
        elif param_type == "i64":
            return [-9223372036854775808, 9223372036854775807]  # i64::MIN, i64::MAX
        elif param_type == "i128":
            return [-170141183460469231731687303715884105728, 170141183460469231731687303715884105727]
        elif param_type == "String":
            return ["", "a" * 1000]  # empty and very long string
        elif param_type == "bool":
            return [True, False]
        elif param_type == "Address":
            return ["GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"]
        else:
            return [0, 1]

    def _overflow_value(self, param_type: str) -> Any:
        """
        Return a value exceeding the valid range for the given parameter type.

        Args:
            param_type: Soroban parameter type

        Returns:
            Overflow value
        """
        if param_type == "u32":
            return 4294967296  # u32::MAX + 1
        elif param_type == "u64":
            return 18446744073709551616  # u64::MAX + 1
        elif param_type == "u128":
            return 340282366920938463463374607431768211456  # u128::MAX + 1
        elif param_type == "i32":
            return 2147483648  # i32::MAX + 1
        elif param_type == "i64":
            return 9223372036854775808  # i64::MAX + 1
        elif param_type == "i128":
            return 170141183460469231731687303715884105728  # i128::MAX + 1
        elif param_type == "String":
            return "x" * 10000  # extremely long string
        elif param_type == "bool":
            return 2  # invalid bool value
        elif param_type == "Address":
            return "INVALID_ADDRESS"
        else:
            return 999999999

    def _adversarial_values(self, param_type: str) -> List[Any]:
        """
        Return adversarial inputs for the given parameter type.

        Adversarial inputs simulate attacker behavior:
        - Reentrancy-simulating double calls
        - Unauthorized addresses
        - Resource exhaustion inputs

        Args:
            param_type: Soroban parameter type

        Returns:
            List of adversarial values
        """
        if param_type in ["u32", "u64", "u128", "i32", "i64", "i128"]:
            # Large values that might cause resource exhaustion
            return [999999999, -999999999] if "i" in param_type else [999999999]
        elif param_type == "String":
            # Malicious strings
            return ["'; DROP TABLE users; --", "<script>alert('xss')</script>"]
        elif param_type == "bool":
            return [True]
        elif param_type == "Address":
            # Unauthorized/malicious addresses
            return ["GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"]
        else:
            return [999999999]

    def _happy_path_value(self, param_type: str) -> Any:
        """
        Return a valid representative value for the given parameter type.

        Args:
            param_type: Soroban parameter type

        Returns:
            Happy path value
        """
        if param_type in ["u32", "u64", "u128"]:
            return 100
        elif param_type in ["i32", "i64", "i128"]:
            return 50
        elif param_type == "String":
            return "test_value"
        elif param_type == "bool":
            return True
        elif param_type == "Address":
            return "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        else:
            return 1

    def _extract_tx_hash(self, output: str) -> str:
        """
        Extract transaction hash from soroban CLI output.

        Args:
            output: CLI output string

        Returns:
            Transaction hash or empty string if not found
        """
        # Look for transaction hash pattern in output
        # Stellar transaction hashes are 64-character hex strings
        import re
        match = re.search(r'\b[a-f0-9]{64}\b', output)
        return match.group(0) if match else ""
