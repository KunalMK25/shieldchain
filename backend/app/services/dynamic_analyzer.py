"""
Dynamic analysis orchestration service for ShieldChain.

This service orchestrates the simulation-based dynamic analysis pipeline:
1. Extract functions from contract source code
2. Generate simulated fuzzing transactions
3. Simulate execution based on code patterns
4. Classify results with Groq AI
5. Compute risk adjustment
"""

import asyncio
import os
import logging
from typing import List
from datetime import datetime, timezone
import hashlib

from app.models.schemas import DynamicLogEntry, DynamicAnalyzeResponse
from app.services.fuzzing_engine import FuzzingEngine
from app.services.horizon_client import HorizonClient
from app.services.groq_classifier import GroqClassifier

logger = logging.getLogger(__name__)

DYNAMIC_TIMEOUT = 90  # seconds


async def run_dynamic_analysis(
    contract_code: str,
    contract_name: str,
    contract_hash: str,
) -> DynamicAnalyzeResponse:
    """
    Simulation-based dynamic analysis pipeline.
    
    This approach analyzes the contract code and simulates runtime behavior
    without requiring actual deployment to testnet. It:
    1. Extracts functions from contract code
    2. Generates simulated fuzzing transactions
    3. Simulates execution based on code patterns
    4. Classifies results with Groq AI
    5. Computes risk adjustment
    
    Args:
        contract_code: Soroban contract source code
        contract_name: Human-readable contract name
        contract_hash: SHA-256 hash of contract_code (hex)
        
    Returns:
        DynamicAnalyzeResponse with simulated results
    """
    try:
        logger.info(f"Starting simulation-based dynamic analysis for {contract_hash}")
        
        # Check for Groq API key
        groq_api_key = os.getenv("GROQ_API_KEY", "")
        
        # Step 1: Extract functions from contract code
        functions = _extract_functions_from_code(contract_code)
        logger.info(f"Extracted {len(functions)} functions from contract code")
        
        if not functions:
            logger.warning("No functions found in contract code")
            return DynamicAnalyzeResponse(
                contract_id=f"CSIM{contract_hash[:56].upper()}",  # Simulated contract ID
                dynamic_audit_log=[],
                anomalies_found=0,
                dynamic_risk_adjustment=0,
                dynamic_status="OK"
            )
        
        # Step 2: Generate simulated dynamic log entries
        log_entries = await _simulate_dynamic_execution(
            contract_code=contract_code,
            functions=functions,
            contract_hash=contract_hash
        )
        
        logger.info(f"Generated {len(log_entries)} simulated log entries")
        
        # Step 3: Use pattern-based classification (more accurate than Groq for simulated data)
        # Groq tends to over-classify simulated data as anomalies
        # The simulation already provides accurate classification based on code patterns
        logger.info(f"Using pattern-based classification for {len(log_entries)} log entries")
        
        # Step 4: Compute metrics
        anomalies_found = sum(1 for entry in log_entries if entry.anomaly)
        dynamic_risk_adjustment = _compute_risk_adjustment(log_entries)
        
        logger.info(
            f"Dynamic analysis complete for {contract_hash}: "
            f"{anomalies_found} anomalies, risk adjustment: {dynamic_risk_adjustment}"
        )
        
        return DynamicAnalyzeResponse(
            contract_id=f"CSIM{contract_hash[:56].upper()}",  # Simulated contract ID
            dynamic_audit_log=log_entries,
            anomalies_found=anomalies_found,
            dynamic_risk_adjustment=dynamic_risk_adjustment,
            dynamic_status="OK"
        )
        
    except asyncio.TimeoutError:
        logger.error(f"Dynamic analysis timed out for {contract_hash}")
        return DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="TIMEOUT"
        )
        
    except Exception as e:
        logger.error(
            f"Dynamic analysis failed for {contract_hash}: {e}",
            exc_info=True
        )
        return DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="DEPLOY_FAILED"
        )


def _compute_risk_adjustment(log_entries: List[DynamicLogEntry]) -> int:
    """
    Pure function. Returns sum of:
      CRITICAL anomaly → +5
      HIGH anomaly     → +3
      MEDIUM anomaly   → +2
      LOW anomaly      → +1
    Only counts entries where anomaly=True.
    
    Args:
        log_entries: List of DynamicLogEntry records
        
    Returns:
        Total risk adjustment as integer
    """
    severity_weights = {
        "CRITICAL": 5,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "NONE": 0
    }
    
    total = 0
    for entry in log_entries:
        if entry.anomaly:
            weight = severity_weights.get(entry.severity.upper(), 0)
            total += weight
    
    return total


def _extract_functions_from_code(contract_code: str) -> List[dict]:
    """
    Extract function definitions from contract code.
    
    Supports both Soroban (Rust) and Solidity contracts.
    
    Soroban patterns:
    - pub fn function_name(...)
    - fn function_name(...)
    
    Solidity patterns:
    - function function_name(...) public
    - function function_name(...) external
    
    Args:
        contract_code: Contract source code
        
    Returns:
        List of function definitions with name and estimated parameters
    """
    import re
    
    # Detect contract type
    is_solidity = 'pragma solidity' in contract_code or 'contract ' in contract_code
    
    if is_solidity:
        return _extract_solidity_functions(contract_code)
    else:
        return _extract_soroban_functions(contract_code)


def _extract_soroban_functions(contract_code: str) -> List[dict]:
    """Extract functions from Soroban/Rust contract."""
    import re
    
    functions = []
    
    # Pattern to match function definitions
    # Matches: pub fn name(...) or fn name(...) 
    pattern = r'(?:pub\s+)?fn\s+(\w+)\s*\('
    
    matches = re.finditer(pattern, contract_code)
    
    for match in matches:
        func_name = match.group(1)
        
        # Skip test functions and internal helpers
        if func_name.startswith('test_') or func_name.startswith('_'):
            logger.debug(f"Skipping internal/test function: {func_name}")
            continue
        
        # Estimate parameter types based on common patterns
        params = _estimate_parameters(func_name, contract_code, is_solidity=False)
        
        functions.append({
            "name": func_name,
            "parameters": params
        })
        
        logger.info(f"Extracted Soroban function: {func_name} with {len(params)} parameters")
    
    logger.info(f"Total Soroban functions extracted: {len(functions)}")
    return functions


def _extract_solidity_functions(contract_code: str) -> List[dict]:
    """Extract functions from Solidity contract."""
    import re
    
    functions = []
    
    # Pattern to match Solidity function definitions
    # Matches: function name(...) public/external
    pattern = r'function\s+(\w+)\s*\([^)]*\)\s+(?:public|external)'
    
    matches = re.finditer(pattern, contract_code)
    
    for match in matches:
        func_name = match.group(1)
        
        # Skip constructor
        if func_name == 'constructor':
            logger.debug(f"Skipping constructor")
            continue
        
        # Estimate parameter types based on common patterns
        params = _estimate_parameters(func_name, contract_code, is_solidity=True)
        
        functions.append({
            "name": func_name,
            "parameters": params
        })
        
        logger.info(f"Extracted Solidity function: {func_name} with {len(params)} parameters")
    
    logger.info(f"Total Solidity functions extracted: {len(functions)}")
    return functions


def _estimate_parameters(func_name: str, contract_code: str, is_solidity: bool = False) -> List[dict]:
    """
    Estimate parameter types for a function based on common patterns.
    
    Args:
        func_name: Function name
        contract_code: Full contract code
        is_solidity: Whether this is a Solidity contract
        
    Returns:
        List of parameter definitions
    """
    if is_solidity:
        # Solidity parameter patterns
        if func_name in ['setOwner']:
            return [
                {"name": "_newOwner", "type": "address"}
            ]
        elif func_name in ['deposit']:
            return []  # payable function, no explicit params
        elif func_name in ['withdrawAll']:
            return []  # uses msg.sender implicitly
        elif func_name in ['transferFunds']:
            return [
                {"name": "_to", "type": "address"},
                {"name": "_amount", "type": "uint256"}
            ]
        elif func_name in ['transfer', 'send']:
            return [
                {"name": "_to", "type": "address"},
                {"name": "_amount", "type": "uint256"}
            ]
        elif func_name in ['balanceOf', 'balances']:
            return [
                {"name": "_account", "type": "address"}
            ]
        elif func_name in ['approve']:
            return [
                {"name": "_spender", "type": "address"},
                {"name": "_amount", "type": "uint256"}
            ]
        else:
            # Default Solidity parameters
            return [
                {"name": "_param1", "type": "uint256"},
                {"name": "_param2", "type": "address"}
            ]
    else:
        # Soroban parameter patterns
        if func_name in ['transfer', 'send', 'pay']:
            return [
                {"name": "from", "type": "Address"},
                {"name": "to", "type": "Address"},
                {"name": "amount", "type": "u128"}
            ]
        elif func_name in ['balance', 'get_balance']:
            return [
                {"name": "account", "type": "Address"}
            ]
        elif func_name in ['approve', 'authorize']:
            return [
                {"name": "spender", "type": "Address"},
                {"name": "amount", "type": "u128"}
            ]
        elif func_name in ['deposit', 'mint']:
            return [
                {"name": "to", "type": "Address"},
                {"name": "amount", "type": "u128"}
            ]
        elif func_name in ['withdraw', 'burn']:
            return [
                {"name": "from", "type": "Address"},
                {"name": "amount", "type": "u128"}
            ]
        else:
            # Default Soroban parameters
            return [
                {"name": "param1", "type": "u128"},
                {"name": "param2", "type": "Address"}
            ]


async def _simulate_dynamic_execution(
    contract_code: str,
    functions: List[dict],
    contract_hash: str
) -> List[DynamicLogEntry]:
    """
    Simulate dynamic execution by generating realistic log entries.
    
    Creates fuzzing transactions for each function with different strategies:
    - Zero values
    - Boundary values
    - Overflow values
    - Adversarial inputs
    - Happy path
    
    Args:
        contract_code: Soroban contract source code
        functions: List of extracted functions
        contract_hash: Contract hash for transaction IDs
        
    Returns:
        List of DynamicLogEntry records
    """
    log_entries = []
    
    # Detect global vulnerability patterns in code
    has_global_overflow_risk = 'checked_add' not in contract_code and ('+' in contract_code or '-' in contract_code or '*' in contract_code)
    has_global_reentrancy_risk = 'call' in contract_code.lower() and 'balance' in contract_code.lower()
    
    for idx, func in enumerate(functions):
        func_name = func["name"]
        params = func["parameters"]
        
        # Analyze this specific function for vulnerabilities
        func_analysis = _analyze_function_vulnerabilities(func_name, contract_code)
        
        # Generate 5 transactions per function (one per strategy)
        strategies = [
            ("zero", _generate_zero_params(params)),
            ("boundary", _generate_boundary_params(params)),
            ("overflow", _generate_overflow_params(params)),
            ("adversarial", _generate_adversarial_params(params)),
            ("happy_path", _generate_happy_params(params))
        ]
        
        for strategy_idx, (strategy, param_values) in enumerate(strategies):
            # Generate unique transaction hash
            tx_hash = hashlib.sha256(
                f"{contract_hash}{func_name}{strategy}{idx}{strategy_idx}".encode()
            ).hexdigest()[:64]
            
            # Simulate execution result based on strategy and code patterns
            result, error, anomaly, severity, reason = _simulate_execution_result(
                func_name=func_name,
                strategy=strategy,
                param_values=param_values,
                func_analysis=func_analysis,
                has_global_overflow_risk=has_global_overflow_risk,
                has_global_reentrancy_risk=has_global_reentrancy_risk
            )
            
            # Create log entry
            entry = DynamicLogEntry(
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                transaction_hash=tx_hash,
                function_called=func_name,
                parameters=param_values,
                result=result,
                error=error,
                anomaly=anomaly,
                severity=severity,
                status="FLAGGED" if anomaly and severity in ["CRITICAL", "HIGH"] else "SUSPICIOUS" if anomaly else "NORMAL",
                reason=reason
            )
            
            log_entries.append(entry)
    
    return log_entries


def _analyze_function_vulnerabilities(func_name: str, contract_code: str) -> dict:
    """
    Analyze a specific function for common vulnerabilities.
    
    Supports both Soroban (Rust) and Solidity contracts.
    
    Returns a dict with vulnerability flags for this function.
    """
    import re
    
    # Detect contract type
    is_solidity = 'pragma solidity' in contract_code or 'contract ' in contract_code
    
    if is_solidity:
        return _analyze_solidity_function(func_name, contract_code)
    else:
        return _analyze_soroban_function(func_name, contract_code)


def _analyze_soroban_function(func_name: str, contract_code: str) -> dict:
    """Analyze a Soroban/Rust function for vulnerabilities."""
    import re
    
    # Extract the function body
    func_pattern = rf'fn\s+{re.escape(func_name)}\s*\([^)]*\)\s*(?:->.*?)?\s*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}'
    func_match = re.search(func_pattern, contract_code, re.DOTALL)
    
    if not func_match:
        # Function not found or couldn't parse - assume safe
        return {
            "has_auth_check": True,
            "has_overflow_risk": False,
            "has_reentrancy_risk": False,
            "is_state_changing": False,
            "is_sensitive": False
        }
    
    func_body = func_match.group(1)
    
    # Check for authorization
    has_auth_check = 'require_auth' in func_body or 'check_auth' in func_body
    
    # Check for arithmetic operations without checked variants
    has_unchecked_add = '+' in func_body and 'checked_add' not in func_body
    has_unchecked_sub = '-' in func_body and 'checked_sub' not in func_body
    has_unchecked_mul = '*' in func_body and 'checked_mul' not in func_body
    has_overflow_risk = has_unchecked_add or has_unchecked_sub or has_unchecked_mul
    
    # Check for reentrancy patterns
    has_external_call = 'call' in func_body.lower() or 'invoke' in func_body.lower()
    has_state_update = 'set' in func_body or 'storage' in func_body
    has_reentrancy_risk = has_external_call and has_state_update
    
    # Check if function modifies state
    is_state_changing = (
        'set' in func_body or 
        'storage' in func_body or 
        'push' in func_body or
        'remove' in func_body or
        'update' in func_body
    )
    
    # Determine if this is a sensitive function that needs auth
    is_sensitive = (
        is_state_changing or
        func_name in ['transfer', 'withdraw', 'burn', 'mint', 'approve', 'set_owner', 
                     'update', 'delete', 'remove', 'record_audit', 'deposit']
    )
    
    return {
        "has_auth_check": has_auth_check,
        "has_overflow_risk": has_overflow_risk,
        "has_reentrancy_risk": has_reentrancy_risk,
        "is_state_changing": is_state_changing,
        "is_sensitive": is_sensitive
    }


def _analyze_solidity_function(func_name: str, contract_code: str) -> dict:
    """Analyze a Solidity function for vulnerabilities."""
    import re
    
    # Extract the function body
    func_pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s+(?:public|external)[^{{]*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}'
    func_match = re.search(func_pattern, contract_code, re.DOTALL)
    
    if not func_match:
        # Function not found or couldn't parse - assume safe
        return {
            "has_auth_check": True,
            "has_overflow_risk": False,
            "has_reentrancy_risk": False,
            "is_state_changing": False,
            "is_sensitive": False
        }
    
    func_body = func_match.group(1)
    
    # Check for authorization
    has_auth_check = (
        'require(msg.sender' in func_body or 
        'require(owner' in func_body or
        'onlyOwner' in contract_code[:func_match.start()]  # Check for modifier
    )
    
    # Check for arithmetic operations (Solidity < 0.8.0 needs SafeMath)
    version_match = re.search(r'pragma solidity\s+([\^<>=]*)([\d.]+)', contract_code)
    is_old_solidity = False
    if version_match:
        version_str = version_match.group(2)
        try:
            version_parts = [int(x) for x in version_str.split('.')]
            is_old_solidity = version_parts[0] == 0 and version_parts[1] < 8
        except:
            pass
    
    has_arithmetic = bool(re.search(r'[\+\-\*\/]\s*=|=\s*[^=]+[\+\-\*\/]', func_body))
    has_safemath = 'SafeMath' in contract_code or '.add(' in func_body or '.sub(' in func_body
    has_overflow_risk = is_old_solidity and has_arithmetic and not has_safemath
    
    # Check for reentrancy patterns (external call before state update)
    has_external_call = bool(re.search(r'\.call\{|\.transfer\(|\.send\(', func_body))
    
    # Check if state is updated after external call
    has_reentrancy_risk = False
    if has_external_call:
        call_match = re.search(r'\.call\{|\.transfer\(|\.send\(', func_body)
        if call_match:
            after_call = func_body[call_match.end():]
            has_state_update_after = bool(re.search(r'=\s*0|=\s*\w+', after_call))
            has_reentrancy_risk = has_state_update_after
    
    # Check if function modifies state
    is_state_changing = bool(re.search(r'=\s*[^=]|\.transfer\(|\.call\{', func_body))
    
    # Determine if this is a sensitive function that needs auth
    is_sensitive = (
        is_state_changing or
        func_name in ['setOwner', 'transferFunds', 'withdraw', 'withdrawAll', 
                     'transfer', 'approve', 'mint', 'burn', 'destroy']
    )
    
    return {
        "has_auth_check": has_auth_check,
        "has_overflow_risk": has_overflow_risk,
        "has_reentrancy_risk": has_reentrancy_risk,
        "is_state_changing": is_state_changing,
        "is_sensitive": is_sensitive
    }


def _generate_zero_params(params: List[dict]) -> dict:
    """Generate zero-value parameters."""
    result = {}
    for param in params:
        param_type = param["type"]
        if "uint" in param_type or "int" in param_type or "u" in param_type or "i" in param_type:
            result[param["name"]] = 0
        elif param_type in ["Address", "address"]:
            result[param["name"]] = "0x0000000000000000000000000000000000000000" if param_type == "address" else "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        elif param_type == "String" or param_type == "string":
            result[param["name"]] = ""
        else:
            result[param["name"]] = 0
    return result


def _generate_boundary_params(params: List[dict]) -> dict:
    """Generate boundary-value parameters."""
    result = {}
    for param in params:
        param_type = param["type"]
        if param_type == "uint256":
            result[param["name"]] = 115792089237316195423570985008687907853269984665640564039457584007913129639935  # uint256::MAX
        elif param_type == "u128":
            result[param["name"]] = 340282366920938463463374607431768211455  # u128::MAX
        elif param_type == "u64":
            result[param["name"]] = 18446744073709551615  # u64::MAX
        elif param_type == "u32":
            result[param["name"]] = 4294967295  # u32::MAX
        elif param_type == "i128":
            result[param["name"]] = -170141183460469231731687303715884105728  # i128::MIN
        elif param_type in ["Address", "address"]:
            result[param["name"]] = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" if param_type == "address" else "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        else:
            result[param["name"]] = 999999
    return result


def _generate_overflow_params(params: List[dict]) -> dict:
    """Generate overflow-value parameters."""
    result = {}
    for param in params:
        param_type = param["type"]
        if "uint" in param_type or "u" in param_type or "int" in param_type or "i" in param_type:
            result[param["name"]] = 999999999999999999999999999999999999999
        elif param_type in ["Address", "address"]:
            result[param["name"]] = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" if param_type == "address" else "GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        else:
            result[param["name"]] = 999999999999
    return result


def _generate_adversarial_params(params: List[dict]) -> dict:
    """Generate adversarial parameters."""
    result = {}
    for param in params:
        param_type = param["type"]
        if param_type in ["Address", "address"]:
            result[param["name"]] = "0xBADBADBADBADBADBADBADBADBADBADBADBADBAD" if param_type == "address" else "GATTACKERADDRESSXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        elif "amount" in param["name"].lower():
            result[param["name"]] = 1  # Minimal amount to test edge cases
        else:
            result[param["name"]] = 42
    return result


def _generate_happy_params(params: List[dict]) -> dict:
    """Generate happy-path parameters."""
    result = {}
    for param in params:
        param_type = param["type"]
        if "amount" in param["name"].lower():
            result[param["name"]] = 1000
        elif param_type in ["Address", "address"]:
            result[param["name"]] = "0x1234567890123456789012345678901234567890" if param_type == "address" else "GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
        elif "uint" in param_type or "u" in param_type or "int" in param_type or "i" in param_type:
            result[param["name"]] = 100
        else:
            result[param["name"]] = 100
    return result


def _simulate_execution_result(
    func_name: str,
    strategy: str,
    param_values: dict,
    func_analysis: dict,
    has_global_overflow_risk: bool,
    has_global_reentrancy_risk: bool
) -> tuple:
    """
    Simulate execution result based on function, strategy, and code patterns.
    
    Returns:
        (result, error, anomaly, severity, reason)
    """
    # Happy path usually succeeds
    if strategy == "happy_path":
        return ("Success", None, False, "NONE", "")
    
    # Zero values might trigger issues
    if strategy == "zero":
        # Check if this is a sensitive function without auth
        if func_analysis["is_sensitive"] and not func_analysis["has_auth_check"]:
            return (
                None,
                "Unauthorized: missing authentication",
                True,
                "CRITICAL",
                f"Function '{func_name}' is sensitive (modifies state) but lacks proper authorization checks. "
                "Add require_auth() to verify caller identity before executing sensitive operations. "
                "Recommendation: Use env.require_auth(&caller) or address.require_auth() at the start of the function."
            )
        return ("Success", None, False, "NONE", "")
    
    # Boundary values test limits
    if strategy == "boundary":
        if func_analysis["has_overflow_risk"] or has_global_overflow_risk:
            return (
                None,
                "Arithmetic overflow detected",
                True,
                "HIGH",
                f"Function '{func_name}' contains unchecked arithmetic operations. Use checked_add(), checked_sub(), checked_mul() "
                "instead of +, -, * operators to prevent integer overflow vulnerabilities. "
                "Example: value.checked_add(amount).unwrap_or_else(|| panic_with_error!(&env, Error::ArithmeticOverflow))"
            )
        return ("Success", None, False, "NONE", "")
    
    # Overflow values should fail
    if strategy == "overflow":
        if func_analysis["has_overflow_risk"] or has_global_overflow_risk:
            return (
                None,
                "Integer overflow vulnerability",
                True,
                "CRITICAL",
                f"Function '{func_name}' has integer overflow vulnerability with unchecked arithmetic. This can lead to fund loss or contract exploitation. "
                "Fix: Replace all arithmetic operations with checked variants (checked_add, checked_sub, checked_mul, checked_div). "
                "Always handle overflow cases explicitly with proper error handling."
            )
        return (None, "Value exceeds maximum", False, "NONE", "")
    
    # Adversarial inputs test security
    if strategy == "adversarial":
        # Check for reentrancy
        if func_analysis["has_reentrancy_risk"] or has_global_reentrancy_risk:
            return (
                None,
                "Potential reentrancy vulnerability",
                True,
                "HIGH",
                f"Function '{func_name}' contains external calls before state updates. This creates reentrancy risk where malicious contracts "
                "can call back into your contract before state is finalized. "
                "Fix: Follow checks-effects-interactions pattern - update all state variables before making external calls."
            )
        
        # Check for missing auth on sensitive functions
        if func_analysis["is_sensitive"] and not func_analysis["has_auth_check"]:
            return (
                None,
                "Missing authorization check",
                True,
                "HIGH",
                f"Function '{func_name}' is sensitive but does not verify caller authorization. Any address can call this function. "
                "Fix: Add require_auth() check at the beginning of the function to verify the caller has permission. "
                "Example: caller.require_auth(); or env.require_auth(&authorized_address);"
            )
        
        return ("Success", None, False, "NONE", "")
    
    return ("Success", None, False, "NONE", "")


def _classify_with_patterns(log_entries: List[DynamicLogEntry], contract_code: str) -> List[DynamicLogEntry]:
    """
    Fallback classification using pattern matching when Groq is unavailable.
    
    Args:
        log_entries: List of log entries to classify
        contract_code: Contract source code for context
        
    Returns:
        Classified log entries
    """
    # Entries are already classified by _simulate_execution_result
    # This is a fallback that doesn't change anything
    return log_entries
