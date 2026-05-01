from groq import Groq
import os
import json
import logging
from dotenv import load_dotenv
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

env_path = Path(__file__).resolve().parents[3] / '.env'
load_dotenv(dotenv_path=env_path)

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

SYSTEM_PROMPT = """You are ShieldChain, an expert Soroban smart contract security auditor.
You analyze Soroban/Rust smart contracts and identify vulnerabilities.
You always respond with valid JSON only — no markdown, no backticks, no extra text."""


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_vulnerabilities(items: Any) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    if not isinstance(items, list):
        return normalized

    for item in items:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "title": str(item.get("title", "Unknown vulnerability")),
                "severity": str(item.get("severity", "MEDIUM")).upper(),
                "description": str(item.get("description", "")),
                "line": _to_int(item.get("line"), 0),
                "fix": str(item.get("fix", "")),
            }
        )
    return normalized


def _normalize_score_breakdown(item: Any) -> Dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    return {
        "reasoning": str(item.get("reasoning", "")),
        "positives": [str(p) for p in item.get("positives", []) if p] if isinstance(item.get("positives"), list) else [],
        "critical_count": _to_int(item.get("critical_count"), 0),
        "high_count": _to_int(item.get("high_count"), 0),
        "medium_count": _to_int(item.get("medium_count"), 0),
        "low_count": _to_int(item.get("low_count"), 0),
    }


def _normalize_improvement_priority(items: Any) -> List[Dict[str, Any]] | None:
    if not isinstance(items, list):
        return None
    normalized: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "order": _to_int(item.get("order"), 0),
            "fix": str(item.get("fix", "")),
            "effort": str(item.get("effort", "")),
            "severity": str(item.get("severity", "")),
        })
    return normalized if normalized else None


def _normalize_response(raw_obj: Dict[str, Any]) -> Dict[str, Any]:
    vulnerabilities = _normalize_vulnerabilities(raw_obj.get("vulnerabilities", []))
    
    # Recalculate risk score based on actual vulnerabilities
    # Don't trust the AI's risk score - calculate it ourselves
    risk_score = _calculate_risk_score(vulnerabilities)
    
    # Debug logging
    logger.info(f"Normalized {len(vulnerabilities)} vulnerabilities, calculated risk_score={risk_score}")
    
    result = {
        "risk_score": risk_score,
        "vulnerabilities": vulnerabilities,
        "exploit_story": str(raw_obj.get("exploit_story", "")),
    }
    
    # Extract optional fields - return None if absent
    score_breakdown = _normalize_score_breakdown(raw_obj.get("score_breakdown"))
    if score_breakdown:
        # Update the counts in score_breakdown to match actual vulnerabilities
        severity_counts = _count_by_severity(vulnerabilities)
        score_breakdown["critical_count"] = severity_counts["CRITICAL"]
        score_breakdown["high_count"] = severity_counts["HIGH"]
        score_breakdown["medium_count"] = severity_counts["MEDIUM"]
        score_breakdown["low_count"] = severity_counts["LOW"]
        result["score_breakdown"] = score_breakdown
    
    improvement_priority = _normalize_improvement_priority(raw_obj.get("improvement_priority"))
    if improvement_priority:
        result["improvement_priority"] = improvement_priority
    
    return result


def _count_by_severity(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count vulnerabilities by severity level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "MEDIUM").upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def _calculate_risk_score(vulnerabilities: List[Dict[str, Any]]) -> int:
    """
    Calculate risk score based on vulnerability severity.
    
    Scoring system:
    - CRITICAL: 25 points each
    - HIGH: 15 points each
    - MEDIUM: 8 points each
    - LOW: 3 points each
    
    Score capped at 100.
    """
    score = 0
    severity_weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "MEDIUM").upper()
        score += severity_weights.get(severity, 5)
    
    # Cap at 100
    return min(score, 100)


def analyze_contract(contract_code: str) -> dict:
    """
    Analyze a smart contract for security vulnerabilities.
    
    Supports both Soroban (Rust) and Solidity contracts.
    Uses Groq AI for analysis, with fallback to basic pattern matching if API fails.
    """
    # Detect contract type
    is_solidity = 'pragma solidity' in contract_code or 'contract ' in contract_code
    
    try:
        return _analyze_with_groq(contract_code, is_solidity)
    except Exception as e:
        error_msg = str(e).lower()
        
        # Check if it's a rate limit error
        if "rate limit" in error_msg or "429" in error_msg:
            logger.warning(f"Groq API rate limit reached, using fallback analysis: {e}")
            fallback_result = _fallback_analysis(contract_code, is_solidity)
            # Normalize the fallback result to calculate risk score
            return _normalize_response(fallback_result)
        
        # For other errors, also use fallback
        logger.error(f"Groq API error, using fallback analysis: {e}")
        fallback_result = _fallback_analysis(contract_code, is_solidity)
        # Normalize the fallback result to calculate risk score
        return _normalize_response(fallback_result)


def _analyze_with_groq(contract_code: str, is_solidity: bool = False) -> dict:
    contract_type = "Solidity (Ethereum)" if is_solidity else "Soroban (Stellar)"
    
    prompt = f"""
Analyze this {contract_type} smart contract for security vulnerabilities.

Return ONLY valid JSON with this exact structure:
{{
    "risk_score": <number>,
    "vulnerabilities": [
        {{
            "title": "<short title>",
            "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
            "description": "<what is wrong>",
            "line": <number>,
            "fix": "<exact code fix>",
        }}
    ],
    "exploit_story": "<step by step how a hacker would exploit this>",
    "score_breakdown": {{
        "reasoning": "<explain why the risk score is this specific number>",
        "positives": ["<positive security aspect 1>", "<positive security aspect 2>"],
        "critical_count": <number of CRITICAL vulnerabilities>,
        "high_count": <number of HIGH vulnerabilities>,
        "medium_count": <number of MEDIUM vulnerabilities>,
        "low_count": <number of LOW vulnerabilities>
    }},
    "improvement_priority": [
        {{
            "order": <priority number starting from 1>,
            "fix": "<what to fix>",
            "effort": "<Low|Medium|High>",
            "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
        }}
    ]
}}

Contract to analyze:
{contract_code}
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
        max_tokens=4000
    )

    raw = response.choices[0].message.content.strip()

    # Clean markdown if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    parsed = json.loads(raw)
    return _normalize_response(parsed)



def _fallback_analysis(contract_code: str, is_solidity: bool = False) -> dict:
    """
    Fallback analysis when Groq API is unavailable or rate limited.
    
    Performs basic pattern matching to detect common vulnerabilities.
    Supports both Soroban (Rust) and Solidity contracts.
    """
    vulnerabilities = []
    
    if is_solidity:
        # Solidity-specific vulnerability detection
        vulnerabilities.extend(_detect_solidity_vulnerabilities(contract_code))
    else:
        # Soroban/Rust-specific vulnerability detection
        vulnerabilities.extend(_detect_soroban_vulnerabilities(contract_code))
    
    # Note: risk_score will be recalculated by _normalize_response using _calculate_risk_score
    # So we just pass a placeholder here
    
    contract_type = "Solidity" if is_solidity else "Soroban"
    
    return {
        "risk_score": 0,  # Will be recalculated by _normalize_response
        "vulnerabilities": vulnerabilities,
        "exploit_story": f"Note: This analysis used pattern matching as a fallback. For comprehensive security assessment, please try again when the AI service is available, or consider a manual code review for this {contract_type} contract.",
        "score_breakdown": {
            "reasoning": f"Pattern matching analysis performed on {contract_type} contract. AI-powered analysis temporarily unavailable.",
            "positives": [f"Contract structure appears valid", f"Uses {contract_type} syntax"],
            "critical_count": 0,
            "high_count": sum(1 for v in vulnerabilities if v["severity"] == "HIGH"),
            "medium_count": sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM"),
            "low_count": sum(1 for v in vulnerabilities if v["severity"] == "LOW")
        }
    }


def _detect_soroban_vulnerabilities(contract_code: str) -> List[Dict[str, Any]]:
    """Detect vulnerabilities in Soroban/Rust contracts."""
    vulnerabilities = []
    
    # Check for missing authorization
    if 'require_auth' not in contract_code and 'check_auth' not in contract_code:
        vulnerabilities.append({
            "title": "Missing Authorization Checks",
            "severity": "HIGH",
            "description": "Contract does not appear to have authorization checks. Functions may be callable by anyone.",
            "line": 1,
            "fix": "Add require_auth() or check_auth() calls to sensitive functions to verify caller identity."
        })
    
    # Check for unchecked arithmetic
    has_arithmetic = any(op in contract_code for op in ['+', '-', '*', '/'])
    has_checked = any(checked in contract_code for checked in ['checked_add', 'checked_sub', 'checked_mul', 'checked_div'])
    
    if has_arithmetic and not has_checked:
        vulnerabilities.append({
            "title": "Unchecked Arithmetic Operations",
            "severity": "HIGH",
            "description": "Contract uses arithmetic operators without checked variants, risking integer overflow/underflow.",
            "line": 1,
            "fix": "Replace +, -, *, / with checked_add(), checked_sub(), checked_mul(), checked_div() and handle errors appropriately."
        })
    
    # Check for reentrancy patterns
    if 'call' in contract_code.lower() and 'storage' in contract_code.lower():
        vulnerabilities.append({
            "title": "Potential Reentrancy Risk",
            "severity": "MEDIUM",
            "description": "Contract contains external calls and state modifications, which may be vulnerable to reentrancy.",
            "line": 1,
            "fix": "Follow checks-effects-interactions pattern: update state before making external calls."
        })
    
    # Check for panic usage
    if 'panic!' in contract_code or 'unwrap()' in contract_code:
        vulnerabilities.append({
            "title": "Unsafe Error Handling",
            "severity": "LOW",
            "description": "Contract uses panic! or unwrap() which can cause unexpected contract termination.",
            "line": 1,
            "fix": "Use proper error handling with Result types and custom error enums instead of panic!."
        })
    
    return vulnerabilities


def _detect_solidity_vulnerabilities(contract_code: str) -> List[Dict[str, Any]]:
    """Detect vulnerabilities in Solidity contracts."""
    import re
    
    vulnerabilities = []
    
    # Extract Solidity version
    version_match = re.search(r'pragma solidity\s+([\^<>=]*)([\d.]+)', contract_code)
    solidity_version = None
    if version_match:
        version_str = version_match.group(2)
        try:
            # Parse version (e.g., "0.6.0" -> [0, 6, 0])
            solidity_version = [int(x) for x in version_str.split('.')]
        except:
            pass
    
    # 1. Check for improper access control
    # Find public functions without proper modifiers
    public_functions = re.findall(r'function\s+(\w+)\s*\([^)]*\)\s+public', contract_code)
    
    for func_name in public_functions:
        # Check if function has access control
        func_pattern = rf'function\s+{re.escape(func_name)}\s*\([^)]*\)\s+public[^{{]*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}'
        func_match = re.search(func_pattern, contract_code, re.DOTALL)
        
        if func_match:
            func_body = func_match.group(1)
            
            # Check for sensitive operations without access control
            has_state_change = any(keyword in func_body for keyword in ['=', 'transfer', 'call', 'delegatecall', 'selfdestruct'])
            has_access_control = any(check in func_body for check in ['require(msg.sender', 'onlyOwner', 'require(owner'])
            
            if has_state_change and not has_access_control:
                vulnerabilities.append({
                    "title": f"Improper Access Control in {func_name}",
                    "severity": "CRITICAL",
                    "description": f"Public function '{func_name}' modifies state without proper access control. Anyone can call this function.",
                    "line": contract_code[:func_match.start()].count('\n') + 1,
                    "fix": f"Add access control modifier (e.g., 'onlyOwner') or require statement: require(msg.sender == owner, 'Unauthorized');"
                })
    
    # 2. Check for integer overflow/underflow (Solidity < 0.8.0)
    if solidity_version and solidity_version[0] == 0 and solidity_version[1] < 8:
        has_arithmetic = bool(re.search(r'[\+\-\*\/]\s*=|=\s*[^=]+[\+\-\*\/]', contract_code))
        has_safemath = 'SafeMath' in contract_code or 'using SafeMath' in contract_code
        
        if has_arithmetic and not has_safemath:
            vulnerabilities.append({
                "title": "Integer Overflow/Underflow Risk",
                "severity": "CRITICAL",
                "description": f"Contract uses Solidity {version_match.group(1)}{version_match.group(2)} which does not have built-in overflow protection. Arithmetic operations can wrap around.",
                "line": 1,
                "fix": "Use SafeMath library for all arithmetic operations, or upgrade to Solidity ^0.8.0 which has built-in overflow checks."
            })
    
    # 3. Check for reentrancy vulnerability
    # Look for external calls before state updates
    functions_with_calls = re.finditer(
        r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        contract_code,
        re.DOTALL
    )
    
    for func_match in functions_with_calls:
        func_name = func_match.group(1)
        func_body = func_match.group(2)
        
        # Check for external call followed by state update
        has_external_call = bool(re.search(r'\.call\{|\.transfer\(|\.send\(', func_body))
        
        if has_external_call:
            # Find position of external call and state updates
            call_pos = re.search(r'\.call\{|\.transfer\(|\.send\(', func_body)
            state_update_after = re.search(r'=\s*0|=\s*\w+', func_body[call_pos.end():]) if call_pos else None
            
            if state_update_after:
                vulnerabilities.append({
                    "title": f"Reentrancy Vulnerability in {func_name}",
                    "severity": "CRITICAL",
                    "description": f"Function '{func_name}' makes external call before updating state. Malicious contracts can re-enter and exploit this.",
                    "line": contract_code[:func_match.start()].count('\n') + 1,
                    "fix": "Follow checks-effects-interactions pattern: update all state variables BEFORE making external calls. Use ReentrancyGuard modifier."
                })
    
    # 4. Check for lack of input validation
    functions = re.finditer(
        r'function\s+(\w+)\s*\(([^)]*)\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        contract_code,
        re.DOTALL
    )
    
    for func_match in functions:
        func_name = func_match.group(1)
        params = func_match.group(2)
        func_body = func_match.group(3)
        
        # Check if function has parameters but no validation
        if params.strip() and 'uint' in params:
            has_require = 'require(' in func_body
            has_arithmetic = bool(re.search(r'[\+\-\*]', func_body))
            
            if has_arithmetic and not has_require:
                vulnerabilities.append({
                    "title": f"Lack of Input Validation in {func_name}",
                    "severity": "MEDIUM",
                    "description": f"Function '{func_name}' performs arithmetic on parameters without validation. This can lead to unexpected behavior.",
                    "line": contract_code[:func_match.start()].count('\n') + 1,
                    "fix": "Add require() statements to validate input parameters (e.g., require(amount > 0, 'Invalid amount'))."
                })
    
    # 5. Check for use of deprecated patterns
    if '.call.value(' in contract_code or 'throw' in contract_code:
        vulnerabilities.append({
            "title": "Use of Deprecated Patterns",
            "severity": "MEDIUM",
            "description": "Contract uses deprecated Solidity patterns like .call.value() or throw.",
            "line": 1,
            "fix": "Use modern Solidity patterns: .call{value: amount}() instead of .call.value(), and revert() instead of throw."
        })
    
    return vulnerabilities
