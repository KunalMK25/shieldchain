from groq import Groq
import os
import json
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parents[3] / '.env'
load_dotenv(dotenv_path=env_path)

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

SYSTEM_PROMPT = """You are ShieldChain, an expert Soroban smart contract security auditor.
You analyze Soroban/Rust smart contracts and identify vulnerabilities.
You always respond with valid JSON only — no markdown, no backticks, no extra text."""

def analyze_contract(contract_code: str) -> dict:
    prompt = f"""
Analyze this Soroban smart contract for security vulnerabilities.

Return ONLY valid JSON with this exact structure:
{{
    "risk_score": <integer 0-100>,
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW|SAFE>",
    "summary": "<one sentence summary>",
    "vulnerabilities": [
        {{
            "id": "<vuln-001>",
            "type": "<vulnerability type>",
            "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
            "line": <line number or null>,
            "title": "<short title>",
            "description": "<what is wrong>",
            "impact": "<what can happen>",
            "fix": "<exact code fix>",
            "score_contribution": <integer>
        }}
    ],
    "score_breakdown": {{
        "reasoning": "<why this score>",
        "positives": ["<things done correctly>"],
        "critical_count": <integer>,
        "high_count": <integer>,
        "medium_count": <integer>,
        "low_count": <integer>
    }},
    "improvement_priority": [
        {{
            "order": <integer>,
            "fix": "<what to fix>",
            "effort": "<5 min|30 min|2 hours>",
            "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
        }}
    ],
    "exploit_story": "<step by step how a hacker would exploit this>"
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

    return json.loads(raw)