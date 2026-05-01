"""
Tests for the FuzzingEngine service.

Includes property-based tests (P1, P4) and unit tests for fuzzing transaction
generation and execution.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from hypothesis import given, settings, strategies as st

from app.services.fuzzing_engine import FuzzingEngine, FuzzTransaction, FuzzResult


# ============================================================================
# Property-Based Tests
# ============================================================================

# Feature: dynamic-analysis-sentinel-audit, Property 1: Fuzzing input coverage
@given(
    function_name=st.text(min_size=1, max_size=50),
    param_types=st.lists(
        st.sampled_from(FuzzingEngine.PARAM_TYPES),
        min_size=1,
        max_size=5
    )
)
@settings(max_examples=100, deadline=None)
def test_fuzzing_input_coverage(function_name, param_types):
    """
    **Validates: Requirements 1.4, 2.1, 2.8**

    Property 1: For any function signature, generate_inputs produces at least
    one transaction per strategy (5 total minimum).

    For any function name and any list of parameter types, generate_inputs must
    produce at least one transaction per strategy (zero, boundary, overflow,
    adversarial, happy_path) and at least 5 total per function.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    # Build ABI with one function
    abi = [{
        "name": function_name,
        "parameters": [
            {"name": f"param_{i}", "type": param_type}
            for i, param_type in enumerate(param_types)
        ]
    }]

    # Act
    transactions = engine.generate_inputs(abi)

    # Assert: At least 5 transactions generated
    assert len(transactions) >= 5, \
        f"Expected at least 5 transactions, got {len(transactions)}"

    # Assert: All strategies present
    strategies = {tx.strategy for tx in transactions}
    required_strategies = {"zero", "boundary", "overflow", "adversarial", "happy_path"}
    assert required_strategies.issubset(strategies), \
        f"Missing strategies: {required_strategies - strategies}"

    # Assert: At least one transaction per required strategy
    for strategy in required_strategies:
        strategy_txs = [tx for tx in transactions if tx.strategy == strategy]
        assert len(strategy_txs) >= 1, \
            f"Expected at least 1 {strategy} transaction, got {len(strategy_txs)}"

    # Assert: All transactions have the correct function name
    for tx in transactions:
        assert tx.function_name == function_name


# Feature: dynamic-analysis-sentinel-audit, Property 4: All transactions recorded
@given(
    transactions=st.lists(
        st.builds(
            FuzzTransaction,
            function_name=st.text(min_size=1, max_size=20),
            parameters=st.dictionaries(
                st.text(min_size=1, max_size=10),
                st.integers(min_value=0, max_value=1000),
                min_size=0,
                max_size=3
            ),
            strategy=st.sampled_from(["zero", "boundary", "overflow", "adversarial", "happy_path"])
        ),
        min_size=1,
        max_size=10
    )
)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_all_transactions_recorded(transactions):
    """
    **Validates: Requirements 2.5, 2.7**

    Property 4: For any list of N FuzzTransactions (some failing), execute_all
    returns exactly N FuzzResults.

    For any list of N FuzzTransaction objects where some raise exceptions,
    execute_all must return exactly N FuzzResult objects.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    # Mock subprocess execution with random failures
    async def mock_subprocess(*args, **kwargs):
        mock_process = AsyncMock()
        mock_process.returncode = 0 if hash(str(args)) % 3 != 0 else 1
        mock_process.communicate = AsyncMock(
            return_value=(b"success", b"error") if mock_process.returncode != 0 else (b"tx_hash_123", b"")
        )
        return mock_process

    with patch('asyncio.create_subprocess_exec', side_effect=mock_subprocess):
        # Act
        results = await engine.execute_all(transactions, timeout_per_tx=1.0)

        # Assert: Exactly N results returned
        assert len(results) == len(transactions), \
            f"Expected {len(transactions)} results, got {len(results)}"

        # Assert: Each result corresponds to an input transaction
        for i, (tx, result) in enumerate(zip(transactions, results)):
            assert result.function_name == tx.function_name, \
                f"Result {i} function name mismatch"
            assert result.parameters == tx.parameters, \
                f"Result {i} parameters mismatch"
            assert result.strategy == tx.strategy, \
                f"Result {i} strategy mismatch"


# ============================================================================
# Unit Tests
# ============================================================================

@pytest.mark.asyncio
async def test_transaction_timeout_recorded():
    """
    **Validates: Requirements 2.6, 2.7, 2.8**

    Unit test: Verify that transaction timeouts are recorded with timed_out=True.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    transactions = [
        FuzzTransaction(
            function_name="slow_function",
            parameters={"amount": 100},
            strategy="happy_path"
        )
    ]

    # Mock subprocess that never completes
    async def mock_slow_subprocess(*args, **kwargs):
        await asyncio.sleep(100)  # Simulate slow operation
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(b"success", b""))
        return mock_process

    with patch('asyncio.create_subprocess_exec', side_effect=mock_slow_subprocess):
        # Act
        results = await engine.execute_all(transactions, timeout_per_tx=0.1)

        # Assert
        assert len(results) == 1
        result = results[0]
        assert result.timed_out is True, "Expected timed_out=True"
        assert result.error is not None, "Expected error message"
        assert "timeout" in result.error.lower(), "Expected 'timeout' in error message"
        assert result.result is None, "Expected result=None on timeout"


def test_happy_path_transaction_present():
    """
    **Validates: Requirements 2.6, 2.7, 2.8**

    Unit test: Verify at least one happy_path transaction per function.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    abi = [
        {
            "name": "transfer",
            "parameters": [
                {"name": "to", "type": "Address"},
                {"name": "amount", "type": "u64"}
            ]
        },
        {
            "name": "approve",
            "parameters": [
                {"name": "spender", "type": "Address"},
                {"name": "amount", "type": "u64"}
            ]
        }
    ]

    # Act
    transactions = engine.generate_inputs(abi)

    # Assert: At least one happy_path transaction per function
    for func in abi:
        func_name = func["name"]
        happy_path_txs = [
            tx for tx in transactions
            if tx.function_name == func_name and tx.strategy == "happy_path"
        ]
        assert len(happy_path_txs) >= 1, \
            f"Expected at least 1 happy_path transaction for {func_name}"


def test_zero_value_for_each_type():
    """
    **Validates: Requirements 2.6, 2.7, 2.8**

    Unit test: Verify zero values for u32, i128, String, bool, Address.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    # Act & Assert
    assert engine._zero_value("u32") == 0
    assert engine._zero_value("u64") == 0
    assert engine._zero_value("u128") == 0
    assert engine._zero_value("i32") == 0
    assert engine._zero_value("i64") == 0
    assert engine._zero_value("i128") == 0
    assert engine._zero_value("String") == ""
    assert engine._zero_value("bool") is False
    assert engine._zero_value("Address") == "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"


def test_boundary_values_for_types():
    """
    Unit test: Verify boundary values are correct for various types.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    # Act & Assert
    assert engine._boundary_values("u32") == [0, 4294967295]
    assert engine._boundary_values("i32") == [-2147483648, 2147483647]
    assert engine._boundary_values("u128") == [0, 340282366920938463463374607431768211455]
    assert engine._boundary_values("bool") == [True, False]


def test_overflow_values_exceed_limits():
    """
    Unit test: Verify overflow values exceed type limits.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    # Act & Assert
    assert engine._overflow_value("u32") == 4294967296  # u32::MAX + 1
    assert engine._overflow_value("i32") == 2147483648  # i32::MAX + 1
    assert engine._overflow_value("u128") == 340282366920938463463374607431768211456


@pytest.mark.asyncio
async def test_execute_all_handles_subprocess_errors():
    """
    Unit test: Verify that subprocess errors are captured in FuzzResult.error.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    transactions = [
        FuzzTransaction(
            function_name="failing_function",
            parameters={"amount": 100},
            strategy="adversarial"
        )
    ]

    # Mock subprocess that fails
    async def mock_failing_subprocess(*args, **kwargs):
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b"", b"Contract execution failed"))
        return mock_process

    with patch('asyncio.create_subprocess_exec', side_effect=mock_failing_subprocess):
        # Act
        results = await engine.execute_all(transactions, timeout_per_tx=1.0)

        # Assert
        assert len(results) == 1
        result = results[0]
        assert result.error is not None, "Expected error message"
        assert "Contract execution failed" in result.error
        assert result.result is None, "Expected result=None on error"
        assert result.timed_out is False, "Expected timed_out=False on error"


@pytest.mark.asyncio
async def test_execute_all_success_case():
    """
    Unit test: Verify successful transaction execution.
    """
    # Arrange
    engine = FuzzingEngine(
        contract_id="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        stellar_secret_key="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC2",
        network="testnet"
    )

    transactions = [
        FuzzTransaction(
            function_name="transfer",
            parameters={"to": "GADDR", "amount": 100},
            strategy="happy_path"
        )
    ]

    # Mock successful subprocess
    async def mock_success_subprocess(*args, **kwargs):
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(
            return_value=(b"abc123def456abc123def456abc123def456abc123def456abc123def456abcd", b"")
        )
        return mock_process

    with patch('asyncio.create_subprocess_exec', side_effect=mock_success_subprocess):
        # Act
        results = await engine.execute_all(transactions, timeout_per_tx=1.0)

        # Assert
        assert len(results) == 1
        result = results[0]
        assert result.error is None, "Expected no error"
        assert result.result is not None, "Expected result"
        assert result.timed_out is False, "Expected timed_out=False"
        assert len(result.transaction_hash) > 0, "Expected transaction hash"
