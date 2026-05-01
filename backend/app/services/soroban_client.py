from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from dotenv import load_dotenv


env_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(dotenv_path=env_path)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Missing required environment variable: {name}")
    return value


def send_audit_to_soroban(
    contract_hash: str,
    report_hash: str,
    risk_score: int,
    cid: str,
    dynamic_anomalies_count: int = 0,
    dynamic_risk_adjustment: int = 0,
) -> str:
    """
    Send audit data to Soroban contract record_audit function.

    Inputs:
      - contract_hash
      - report_hash
      - risk_score
      - cid
      - dynamic_anomalies_count (default: 0)
      - dynamic_risk_adjustment (default: 0)

    Required .env values:
      - SOROBAN_CONTRACT_ID
      - STELLAR_SECRET_KEY
      - STELLAR_PUBLIC_KEY
      - STELLAR_RPC_URL
      - SOROBAN_NETWORK_PASSPHRASE

    Returns:
      transaction hash (string)
    """
    soroban_contract_id = _required_env("SOROBAN_CONTRACT_ID")
    source_secret = _required_env("STELLAR_SECRET_KEY")
    source_public = _required_env("STELLAR_PUBLIC_KEY")
    rpc_url = _required_env("STELLAR_RPC_URL")
    network_passphrase = _required_env("SOROBAN_NETWORK_PASSPHRASE")

    cmd = [
        "soroban",
        "contract",
        "invoke",
        "--id",
        soroban_contract_id,
        "--source-account",
        source_secret,
        "--rpc-url",
        rpc_url,
        "--network-passphrase",
        network_passphrase,
        "--",
        "record_audit",
        "--auditor",
        source_public,
        "--contract_hash",
        contract_hash,
        "--report_hash",
        report_hash,
        "--ipfs_cid",
        cid,
        "--risk_score",
        str(int(risk_score)),
        "--dynamic_anomalies_count",
        str(int(dynamic_anomalies_count)),
        "--dynamic_risk_adjustment",
        str(int(dynamic_risk_adjustment)),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "Soroban invoke failed: "
            f"{result.stderr.strip() or result.stdout.strip() or 'unknown error'}"
        )

    output = f"{result.stdout}\n{result.stderr}".strip()
    match = re.search(r"\b[a-fA-F0-9]{64}\b", output)
    if match:
        return match.group(0)

    # Fallback: return non-empty output if hash isn't easily parseable.
    cleaned = result.stdout.strip()
    if cleaned:
        return cleaned
    raise RuntimeError("Soroban invoke succeeded but transaction hash was not found in output")


def get_audit_from_soroban(contract_hash: str) -> dict:
    """
    Retrieve audit data from Soroban contract get_audit function.

    Inputs:
      - contract_hash: hex string of the contract hash to query

    Required .env values:
      - SOROBAN_CONTRACT_ID
      - STELLAR_RPC_URL
      - SOROBAN_NETWORK_PASSPHRASE

    Returns:
      dict with keys: contract_hash, report_hash, risk_score, ipfs_cid, timestamp, auditor

    Raises:
      RuntimeError: on non-zero CLI exit code or when AuditNotFound appears in stderr
    """
    soroban_contract_id = _required_env("SOROBAN_CONTRACT_ID")
    rpc_url = _required_env("STELLAR_RPC_URL")
    network_passphrase = _required_env("SOROBAN_NETWORK_PASSPHRASE")

    cmd = [
        "stellar",
        "contract",
        "invoke",
        "--id",
        soroban_contract_id,
        "--rpc-url",
        rpc_url,
        "--network-passphrase",
        network_passphrase,
        "--",
        "get_audit",
        "--contract_hash",
        contract_hash,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    
    # Check for AuditNotFound in stderr
    if "AuditNotFound" in result.stderr:
        raise RuntimeError("AuditNotFound: No audit record exists for this contract hash")
    
    # Check for non-zero exit code
    if result.returncode != 0:
        raise RuntimeError(
            f"Stellar CLI invoke failed: "
            f"{result.stderr.strip() or result.stdout.strip() or 'unknown error'}"
        )

    # Parse the output
    # The stellar CLI returns structured data, typically in a format like:
    # AuditRecord { contract_hash: ..., report_hash: ..., risk_score: ..., ipfs_cid: "...", timestamp: ..., auditor: ... }
    output = result.stdout.strip()
    
    if not output:
        raise RuntimeError("Stellar CLI returned empty output")

    try:
        # Parse the structured output
        # Expected format: key-value pairs or JSON-like structure
        audit_data = {}
        
        # Extract contract_hash (32-byte hex = 64 chars)
        contract_hash_match = re.search(r'contract_hash:\s*([a-fA-F0-9]{64})', output)
        if contract_hash_match:
            audit_data['contract_hash'] = contract_hash_match.group(1)
        
        # Extract report_hash (32-byte hex = 64 chars)
        report_hash_match = re.search(r'report_hash:\s*([a-fA-F0-9]{64})', output)
        if report_hash_match:
            audit_data['report_hash'] = report_hash_match.group(1)
        
        # Extract risk_score (integer)
        risk_score_match = re.search(r'risk_score:\s*(\d+)', output)
        if risk_score_match:
            audit_data['risk_score'] = int(risk_score_match.group(1))
        
        # Extract ipfs_cid (string in quotes)
        ipfs_cid_match = re.search(r'ipfs_cid:\s*"([^"]+)"', output)
        if ipfs_cid_match:
            audit_data['ipfs_cid'] = ipfs_cid_match.group(1)
        
        # Extract timestamp (integer)
        timestamp_match = re.search(r'timestamp:\s*(\d+)', output)
        if timestamp_match:
            audit_data['timestamp'] = int(timestamp_match.group(1))
        
        # Extract auditor (Stellar address - typically 56 chars, alphanumeric)
        auditor_match = re.search(r'auditor:\s*([A-Za-z0-9]{50,60})', output)
        if auditor_match:
            audit_data['auditor'] = auditor_match.group(1)
        
        # Verify all required fields are present
        required_fields = ['contract_hash', 'report_hash', 'risk_score', 'ipfs_cid', 'timestamp', 'auditor']
        missing_fields = [field for field in required_fields if field not in audit_data]
        
        if missing_fields:
            raise RuntimeError(f"Failed to parse audit record: missing fields {missing_fields}")
        
        return audit_data
        
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        raise RuntimeError(f"Failed to parse Stellar CLI output: {str(e)}")
