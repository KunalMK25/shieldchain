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
    "risk_score": <number>,
    "vulnerabilities": [
        {{
            "title": "<short title>",
            "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
            "description": "<what is wrong>",
            "line": <number>,
            "fix": "<exact fix>",
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
    print(f"Vulns Found: {len(result['vulnerabilities'])}")
    print()
    for v in result['vulnerabilities']:
        print(f"  [{v['severity']}] {v['title']}")
    print()
    print(f"Exploit    : {result['exploit_story'][:150]}...")
except json.JSONDecodeError as e:
    print(f"JSON parse error: {e}")
    print("Raw output:")
    print(raw[:500])