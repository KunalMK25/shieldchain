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
) -> str:
    """
    Send audit data to Soroban contract record_audit function.

    Inputs:
      - contract_hash
      - report_hash
      - risk_score
      - cid

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
