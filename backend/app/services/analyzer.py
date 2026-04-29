from groq import Groq
import os
import json
from dotenv import load_dotenv
from pathlib import Path
from typing import Any, Dict, List

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


def _normalize_response(raw_obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "risk_score": _to_int(raw_obj.get("risk_score"), 0),
        "vulnerabilities": _normalize_vulnerabilities(raw_obj.get("vulnerabilities", [])),
        "exploit_story": str(raw_obj.get("exploit_story", "")),
    }


def analyze_contract(contract_code: str) -> dict:
    prompt = f"""
Analyze this Soroban smart contract for security vulnerabilities.

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

    parsed = json.loads(raw)
    return _normalize_response(parsed)