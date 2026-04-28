from groq import Groq
import os
import json
from dotenv import load_dotenv

load_dotenv('../.env')

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

VULNERABLE_CONTRACT = """
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Address, token};

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        let token_client = token::Client::new(&env, &env.current_contract_address());
        token_client.transfer(&from, &env.current_contract_address(), &amount);
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let token_client = token::Client::new(&env, &env.current_contract_address());
        token_client.transfer(&env.current_contract_address(), &to, &amount);
        let balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
        env.storage().persistent().set(&to, &(balance - amount));
    }

    pub fn calculate(env: Env, a: i128, b: i128) -> i128 {
        a * b * 1000
    }
}
"""

PROMPT = f"""
You are ShieldChain, an expert Soroban smart contract security auditor.
Analyze this contract for vulnerabilities.

Return ONLY valid JSON, no other text, no markdown, no backticks:
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
    }},
    "improvement_priority": [
        {{
            "order": 1,
            "fix": "<what to fix>",
            "effort": "<5 min|30 min|2 hours>",
            "severity": "<CRITICAL|HIGH|MEDIUM>"
        }}
    ],
    "exploit_story": "<how a hacker exploits this step by step>"
}}

Contract:
{VULNERABLE_CONTRACT}
"""

print("Analyzing contract with Groq...")
print("=" * 50)

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": PROMPT}],
    temperature=0.1
)

raw = response.choices[0].message.content.strip()

# Clean if needed
if raw.startswith("```"):
    raw = raw.split("```")[1]
    if raw.startswith("json"):
        raw = raw[4:]
raw = raw.strip()

try:
    result = json.loads(raw)
    print(f"✅ Analysis complete!")
    print(f"Risk Score : {result['risk_score']}/100")
    print(f"Risk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns Found: {len(result['vulnerabilities'])}")
    print()
    for v in result['vulnerabilities']:
        print(f"  [{v['severity']}] {v['title']}")
    print()
    print(f"Reasoning  : {result['score_breakdown']['reasoning']}")
    print()
    print(f"Exploit    : {result['exploit_story'][:150]}...")
except json.JSONDecodeError as e:
    print(f"JSON parse error: {e}")
    print("Raw output:")
    print(raw[:500])