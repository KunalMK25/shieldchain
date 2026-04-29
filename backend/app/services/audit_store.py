import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


AUDITS_FILE = Path(__file__).resolve().parents[2] / "data" / "audits.json"


def _ensure_store() -> None:
    AUDITS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not AUDITS_FILE.exists():
        AUDITS_FILE.write_text("[]", encoding="utf-8")


def _read_all() -> List[Dict[str, Any]]:
    _ensure_store()
    return json.loads(AUDITS_FILE.read_text(encoding="utf-8"))


def _write_all(records: List[Dict[str, Any]]) -> None:
    AUDITS_FILE.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _sha256_hex(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def register_audit(payload: Dict[str, Any]) -> Dict[str, Any]:
    contract_hash = _sha256_hex(payload["contract_code"])
    report_hash = _sha256_hex(payload["report_text"])
    created_at = datetime.now(timezone.utc).isoformat()
    audit_id = _sha256_hex(f"{contract_hash}:{report_hash}:{created_at}")[:24]

    record = {
        "audit_id": audit_id,
        "contract_hash": contract_hash,
        "report_hash": report_hash,
        "risk_score": payload["analysis"]["risk_score"],
        "risk_level": payload["analysis"]["risk_level"],
        "ipfs_cid": payload.get("ipfs_cid"),
        "auditor": payload.get("auditor", "local-dev"),
        "created_at": created_at,
        "source": "local-store",
    }

    records = _read_all()
    records.append(record)
    _write_all(records)
    return record


def get_history(contract_hash: str) -> List[Dict[str, Any]]:
    records = _read_all()
    return [r for r in records if r["contract_hash"] == contract_hash]
