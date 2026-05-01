"""
LangChain Multi-Agent System for ShieldChain Smart Contract Analysis

This module implements three coordinated agents:
1. VulnerabilityHunterAgent - Finds security vulnerabilities using tools
2. ExploitNarratorAgent - Chains vulnerabilities into attack scenarios
3. RemediationAdvisorAgent - Generates verified code fixes

Each agent uses tools and maintains a full audit trail.
"""

from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
from pathlib import Path
import json
import os
import hashlib
import datetime
import re

# Load environment variables
env_path = Path(__file__).resolve().parents[3] / '.env'
load_dotenv(dotenv_path=env_path)

# ── LLM ────────────────────────────────────────────────────────────────────────
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.1,
    api_key=os.getenv("GROQ_API_KEY")
)

# ── TOOLS ─────────────────────────────────────────────────────────────────────

@tool
def static_analysis_tool(contract_code: str) -> str:
    """Runs static pattern analysis on smart contract code.
    Supports both Soroban (Rust) and Solidity contracts.
    Checks for: missing authorization, unchecked arithmetic,
    reentrancy patterns, unsafe error handling."""
    
    findings = []
    lines = contract_code.split('\n')
    
    # Detect contract type
    is_solidity = 'pragma solidity' in contract_code or 'contract ' in contract_code
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        if is_solidity:
            # Solidity-specific checks
            if 'function' in stripped and 'public' in stripped:
                if any(kw in stripped for kw in ['setOwner', 'withdraw', 'transfer', 'mint', 'burn']):
                    if 'require(msg.sender' not in contract_code[max(0, contract_code.find(stripped)-200):contract_code.find(stripped)+200]:
                        findings.append({
                            "line": i,
                            "type": "MISSING_AUTH",
                            "severity": "CRITICAL",
                            "detail": f"Public function at line {i} may lack authorization check"
                        })
            
            if any(op in stripped for op in [' + ', ' - ', ' * ', ' / ']):
                if 'SafeMath' not in contract_code and 'pragma solidity 0.' in contract_code:
                    version_match = re.search(r'pragma solidity 0\.(\d+)', contract_code)
                    if version_match and int(version_match.group(1)) < 8:
                        findings.append({
                            "line": i,
                            "type": "UNCHECKED_ARITHMETIC",
                            "severity": "CRITICAL",
                            "detail": f"Arithmetic at line {i} without overflow protection (Solidity <0.8.0)"
                        })
            
            if '.call{value:' in stripped or '.call.value(' in stripped:
                findings.append({
                    "line": i,
                    "type": "REENTRANCY_RISK",
                    "severity": "CRITICAL",
                    "detail": f"External call at line {i} may be vulnerable to reentrancy"
                })
        else:
            # Soroban/Rust-specific checks
            if 'pub fn' in stripped and 'require_auth' not in stripped:
                if any(kw in stripped for kw in ['transfer', 'withdraw', 'mint', 'burn', 'set_owner']):
                    findings.append({
                        "line": i,
                        "type": "MISSING_AUTH",
                        "severity": "CRITICAL",
                        "detail": f"Public function at line {i} may lack authorization check"
                    })
            
            if any(op in stripped for op in [' + ', ' - ', ' * ']) and 'checked_' not in stripped:
                if any(t in stripped for t in ['i128', 'u128', 'i64', 'u64']):
                    findings.append({
                        "line": i,
                        "type": "UNCHECKED_ARITHMETIC",
                        "severity": "HIGH",
                        "detail": f"Arithmetic at line {i} without overflow protection"
                    })
            
            if '.unwrap()' in stripped and 'test' not in stripped.lower():
                findings.append({
                    "line": i,
                    "type": "PANIC_ON_UNWRAP",
                    "severity": "MEDIUM",
                    "detail": f"Unhandled .unwrap() at line {i} can cause contract panic"
                })
    
    return json.dumps({
        "static_findings": findings,
        "total_found": len(findings),
        "contract_type": "Solidity" if is_solidity else "Soroban"
    })

@tool
def severity_score_tool(findings_json: str) -> str:
    """Calculates weighted risk score from vulnerability findings.
    CRITICAL=25pts, HIGH=15pts, MEDIUM=8pts, LOW=3pts. Max score=100."""
    try:
        data = json.loads(findings_json)
        findings = data.get("vulnerabilities", data.get("static_findings", []))
    except:
        return json.dumps({"risk_score": 0, "breakdown": {}})
    
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 0
    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for f in findings:
        sev = f.get("severity", "LOW")
        pts = weights.get(sev, 3)
        score += pts
        breakdown[sev] = breakdown.get(sev, 0) + 1
    
    return json.dumps({
        "risk_score": min(score, 100),
        "breakdown": breakdown,
        "reasoning": f"Score calculated from {len(findings)} findings"
    })

@tool
def exploit_chain_tool(vulnerabilities_json: str) -> str:
    """Analyzes how vulnerabilities can be chained together by an attacker.
    Returns a realistic multi-step attack scenario."""
    try:
        vulns = json.loads(vulnerabilities_json)
        if isinstance(vulns, dict):
            vulns = vulns.get("vulnerabilities", [])
    except:
        return json.dumps({"exploit_chain": "Unable to parse vulnerabilities"})
    
    critical = [v for v in vulns if v.get("severity") == "CRITICAL"]
    high = [v for v in vulns if v.get("severity") == "HIGH"]
    
    chain_steps = []
    if critical:
        chain_steps.append(f"Step 1: Attacker identifies {critical[0].get('title', 'critical vulnerability')}")
    if high:
        chain_steps.append(f"Step 2: Combines with {high[0].get('title', 'high severity issue')} to amplify impact")
    if critical or high:
        chain_steps.append("Step 3: Executes attack transaction — funds drained irreversibly")
        chain_steps.append("Step 4: No recourse — contract is immutable, loss is permanent")
    else:
        chain_steps.append("Step 1: Attacker exploits identified vulnerabilities")
        chain_steps.append("Step 2: Impact depends on contract's asset holdings")
    
    return json.dumps({
        "attack_steps": chain_steps,
        "chainable_vulnerabilities": len(critical) + len(high),
        "estimated_impact": "Total contract balance at risk" if critical else "Partial funds at risk"
    })

@tool
def code_fix_tool(vulnerability_json: str) -> str:
    """Generates corrected code for a specific vulnerability.
    Supports both Soroban/Rust and Solidity.
    Returns before/after code snippets with explanation."""
    try:
        vuln = json.loads(vulnerability_json)
    except:
        return json.dumps({"fix": "Unable to parse vulnerability"})
    
    vuln_type = vuln.get("type", "")
    contract_type = vuln.get("contract_type", "Soroban")
    
    if contract_type == "Solidity":
        fixes = {
            "MISSING_AUTH": {
                "before": "function setOwner(address _newOwner) public {",
                "after":  "function setOwner(address _newOwner) public {\n    require(msg.sender == owner, \"Unauthorized\");",
                "explanation": "Add require(msg.sender == owner) to ensure only the current owner can change ownership"
            },
            "UNCHECKED_ARITHMETIC": {
                "before": "balances[msg.sender] += amount;",
                "after":  "// Upgrade to Solidity ^0.8.0 for built-in overflow checks\n// OR use SafeMath:\nbalances[msg.sender] = balances[msg.sender].add(amount);",
                "explanation": "Use SafeMath library or upgrade to Solidity 0.8.0+ for automatic overflow protection"
            },
            "REENTRANCY_RISK": {
                "before": "(bool success, ) = msg.sender.call{value: amount}(\"\");\nbalances[msg.sender] = 0;",
                "after":  "balances[msg.sender] = 0;\n(bool success, ) = msg.sender.call{value: amount}(\"\");",
                "explanation": "Update state BEFORE external calls to prevent reentrancy attacks. Use ReentrancyGuard modifier."
            }
        }
    else:
        fixes = {
            "MISSING_AUTH": {
                "before": "pub fn withdraw(env: Env, to: Address, amount: i128) {",
                "after":  "pub fn withdraw(env: Env, to: Address, amount: i128) {\n    to.require_auth();",
                "explanation": "Add require_auth() as the first line to ensure only authorized addresses can call this function"
            },
            "UNCHECKED_ARITHMETIC": {
                "before": "let total = balance + amount;",
                "after":  "let total = balance.checked_add(amount).unwrap_or_else(|| panic_with_error!(&env, Error::ArithmeticOverflow));",
                "explanation": "Use checked arithmetic to prevent silent integer overflow in release builds"
            },
            "PANIC_ON_UNWRAP": {
                "before": "let value = storage.get(&key).unwrap();",
                "after":  "let value = storage.get(&key).unwrap_or_default();",
                "explanation": "Use unwrap_or_default() or match to handle the None case gracefully"
            }
        }
    
    fix = fixes.get(vuln_type, {
        "before": "// See vulnerability description",
        "after":  "// Apply recommended fix from description",
        "explanation": vuln.get("fix", "Review and apply security best practices")
    })
    return json.dumps(fix)

# ── AGENT 1 — VulnerabilityHunterAgent ───────────────────────────────────────

HUNTER_SYSTEM_PROMPT = """You are VulnerabilityHunterAgent — a smart contract security expert.
You analyze both Soroban (Rust) and Solidity contracts.

Your job is to find ALL security vulnerabilities in the given contract.

PROCESS:
1. First call static_analysis_tool with the contract code to get pattern-based findings
2. Then reason about business logic issues the static tool might have missed
3. Then call severity_score_tool with all findings to compute the risk score
4. Finally return a complete structured analysis

Always think step by step. Show your reasoning. Be thorough.

Return JSON with this structure:
{{
    "risk_score": <0-100>,
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW|SAFE>",
    "summary": "<one sentence>",
    "vulnerabilities": [
        {{
            "id": "vuln-001",
            "type": "<type>",
            "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
            "line": <number or null>,
            "title": "<short title>",
            "description": "<what is wrong>",
            "impact": "<what can happen>",
            "fix": "<exact fix>",
            "score_contribution": <points>
        }}
    ],
    "score_breakdown": {{
        "reasoning": "<why this score>",
        "positives": ["<good things>"],
        "critical_count": <n>,
        "high_count": <n>,
        "medium_count": <n>,
        "low_count": <n>
    }}
}}"""

hunter_tools = [static_analysis_tool, severity_score_tool]

vulnerability_hunter = create_react_agent(
    llm,
    hunter_tools,
    prompt=HUNTER_SYSTEM_PROMPT
)

# ── AGENT 2 — ExploitNarratorAgent ───────────────────────────────────────────

NARRATOR_SYSTEM_PROMPT = """You are ExploitNarratorAgent — you think like an attacker.

Given a list of vulnerabilities, your job is to:
1. Call exploit_chain_tool to identify how vulnerabilities connect
2. Write a vivid, realistic step-by-step exploit story
3. Explain exactly how a malicious actor would exploit this contract

Be specific. Reference line numbers. Show the exact attack transaction sequence.
Return a plain text exploit narrative paragraph."""

narrator_tools = [exploit_chain_tool]

exploit_narrator = create_react_agent(
    llm,
    narrator_tools,
    prompt=NARRATOR_SYSTEM_PROMPT
)

# ── AGENT 3 — RemediationAdvisorAgent ────────────────────────────────────────

ADVISOR_SYSTEM_PROMPT = """You are RemediationAdvisorAgent — a smart contract security remediation expert.

For each vulnerability:
1. Call code_fix_tool to get the corrected code
2. Rank fixes by effort vs risk reduction
3. Return an ordered priority list with copy-paste code fixes

Return JSON:
{{
    "improvement_priority": [
        {{
            "order": 1,
            "fix": "<what to fix>",
            "effort": "<5 min|30 min|2 hours>",
            "severity": "<CRITICAL|HIGH|MEDIUM>",
            "before_code": "<vulnerable code>",
            "after_code": "<fixed code>",
            "explanation": "<why this fix works>"
        }}
    ]
}}"""

advisor_tools = [code_fix_tool]

remediation_advisor = create_react_agent(
    llm,
    advisor_tools,
    prompt=ADVISOR_SYSTEM_PROMPT
)

# ── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────────

async def run_full_analysis(contract_code: str, contract_name: str = "Unknown") -> dict:
    """
    Orchestrates all 3 agents and returns complete analysis with audit logs.
    This is what replaces the single analyze_contract() call.
    """
    audit_log = []
    
    def log(action, data):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "action": action,
            "contract": contract_name,
            "data": data
        }
        audit_log.append(entry)
        print(f"[AUDIT] {entry['timestamp']} | {action}")
        return entry
    
    log("ANALYSIS_STARTED", {"contract_hash": hashlib.sha256(contract_code.encode()).hexdigest()[:16]})
    
    # Agent 1 — Hunt vulnerabilities
    log("AGENT_STARTED", {"agent": "VulnerabilityHunterAgent"})
    
    # Invoke agent with langgraph API
    hunter_result = vulnerability_hunter.invoke({
        "messages": [("user", f"Analyze this smart contract:\n\n{contract_code}")]
    })
    
    # Extract the final message from the agent
    messages = hunter_result.get("messages", [])
    final_message = messages[-1] if messages else None
    raw_output = final_message.content if hasattr(final_message, 'content') else str(final_message)
    
    log("AGENT_COMPLETED", {
        "agent": "VulnerabilityHunterAgent",
        "message_count": len(messages)
    })
    
    # Parse hunter output
    json_match = re.search(r'\{.*\}', raw_output, re.DOTALL)
    try:
        analysis = json.loads(json_match.group() if json_match else raw_output)
    except:
        analysis = {"risk_score": 50, "vulnerabilities": [], "summary": "Analysis completed"}
    
    vulns_json = json.dumps({"vulnerabilities": analysis.get("vulnerabilities", [])})
    
    # Agent 2 — Narrate exploit
    log("AGENT_STARTED", {"agent": "ExploitNarratorAgent"})
    
    narrator_result = exploit_narrator.invoke({
        "messages": [("user", f"Write an exploit narrative for these vulnerabilities:\n\n{vulns_json}")]
    })
    
    narrator_messages = narrator_result.get("messages", [])
    narrator_final = narrator_messages[-1] if narrator_messages else None
    exploit_story = narrator_final.content if hasattr(narrator_final, 'content') else "No exploit story generated."
    
    log("AGENT_COMPLETED", {
        "agent": "ExploitNarratorAgent",
        "message_count": len(narrator_messages)
    })
    
    # Agent 3 — Remediation
    log("AGENT_STARTED", {"agent": "RemediationAdvisorAgent"})
    
    advisor_result = remediation_advisor.invoke({
        "messages": [("user", f"Generate remediation for these vulnerabilities:\n\n{vulns_json}")]
    })
    
    advisor_messages = advisor_result.get("messages", [])
    advisor_final = advisor_messages[-1] if advisor_messages else None
    raw_advice = advisor_final.content if hasattr(advisor_final, 'content') else "{}"
    
    log("AGENT_COMPLETED", {
        "agent": "RemediationAdvisorAgent",
        "message_count": len(advisor_messages)
    })
    
    json_match2 = re.search(r'\{.*\}', raw_advice, re.DOTALL)
    try:
        remediation = json.loads(json_match2.group() if json_match2 else raw_advice)
    except:
        remediation = {"improvement_priority": []}
    
    log("ANALYSIS_COMPLETED", {
        "risk_score": analysis.get("risk_score", 0),
        "vulnerabilities_found": len(analysis.get("vulnerabilities", [])),
        "agents_used": 3
    })
    
    # Save audit log to file
    log_dir = Path(__file__).resolve().parents[2] / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / f"audit_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(log_path, 'w') as f:
        json.dump(audit_log, f, indent=2)
    
    return {
        **analysis,
        "exploit_story": exploit_story,
        "improvement_priority": remediation.get("improvement_priority", []),
        "audit_log": audit_log,
        "agents_used": ["VulnerabilityHunterAgent", "ExploitNarratorAgent", "RemediationAdvisorAgent"]
    }
