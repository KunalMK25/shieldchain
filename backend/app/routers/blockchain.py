from fastapi import APIRouter, HTTPException
from app.models.schemas import AnchorRequest, AnchorResponse, VerifyResponse, HistoryRecord
from app.services.soroban_client import send_audit_to_soroban, get_audit_from_soroban
from app.services.audit_store import get_history, register_audit
from datetime import datetime, timezone
from typing import List
import hashlib
import os
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/blockchain",
    tags=["Blockchain"]
)


@router.post("/anchor", response_model=AnchorResponse)
async def anchor(request: AnchorRequest):
    """
    Anchor audit records to Stellar blockchain with fallback.
    
    1. Check if contract already anchored (allow re-anchoring with updated data)
    2. Try Soroban anchoring (source="stellar")
    3. On failure, fallback to local store (source="local-fallback")
    4. Return AnchorResponse with tx_hash, explorer_url, etc.
    
    Note: In development without Soroban CLI, always uses local fallback.
    """
    # Check if contract already anchored
    existing_history = get_history(request.contract_hash)
    if existing_history:
        # Allow re-anchoring but log it
        logger.info(f"Re-anchoring contract {request.contract_hash} (already has {len(existing_history)} audit(s))")
    
    timestamp = datetime.now(timezone.utc).isoformat()
    contract_address = os.getenv("SOROBAN_CONTRACT_ID", "")
    
    # Check if Soroban CLI is available
    import shutil
    has_soroban_cli = shutil.which("soroban") is not None
    
    # Try Soroban anchoring only if CLI is available
    tx_hash = None
    source = "local-fallback"
    
    if has_soroban_cli:
        try:
            tx_hash = send_audit_to_soroban(
                request.contract_hash,
                request.report_hash,
                request.risk_score,
                request.ipfs_cid,
                request.dynamic_anomalies_count,
                request.dynamic_risk_adjustment
            )
            source = "stellar"
        except Exception as e:
            logger.warning(f"Soroban anchoring failed: {e}. Using local fallback.")
            tx_hash = None
    else:
        logger.info("Soroban CLI not available. Using local fallback for anchoring.")
    
    # Use local fallback if Soroban failed or unavailable
    if tx_hash is None:
        # Create a simulated tx_hash
        hash_input = f"{request.contract_hash}{timestamp}"
        tx_hash = "demo_" + hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        source = "local-fallback"
        
        # Register in local audit store
        # Determine risk level based on risk score
        if request.risk_score >= 85:
            risk_level = "CRITICAL"
        elif request.risk_score >= 70:
            risk_level = "HIGH"
        elif request.risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Create a record directly without double-hashing
        created_at = timestamp
        
        record = {
            "audit_id": hashlib.sha256(f"{request.contract_hash}:{request.report_hash}:{created_at}".encode()).hexdigest()[:24],
            "contract_hash": request.contract_hash,
            "report_hash": request.report_hash,
            "risk_score": request.risk_score,
            "risk_level": risk_level,
            "ipfs_cid": request.ipfs_cid,
            "auditor": "local-dev",
            "created_at": created_at,
            "source": "local-fallback",
        }
        
        # Save directly to audit store
        import json
        from pathlib import Path
        audits_file = Path(__file__).resolve().parents[2] / "data" / "audits.json"
        audits_file.parent.mkdir(parents=True, exist_ok=True)
        
        if audits_file.exists():
            records = json.loads(audits_file.read_text(encoding="utf-8"))
        else:
            records = []
        
        records.append(record)
        audits_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
    
    # Construct explorer URL
    if source == "stellar":
        explorer_url = f"https://stellar.expert/explorer/testnet/tx/{tx_hash}"
    else:
        # For local fallback, link to our verify page instead of Stellar Explorer
        explorer_url = f"http://localhost:3000/verify?hash={request.contract_hash}"
    
    return AnchorResponse(
        tx_hash=tx_hash,
        explorer_url=explorer_url,
        contract_address=contract_address,
        timestamp=timestamp,
        source=source
    )


@router.get("/verify/{contract_hash}", response_model=VerifyResponse)
async def verify(contract_hash: str):
    """
    Verify audit records from blockchain or local store.
    
    1. Try Soroban query (source="stellar")
    2. On failure, check local store (source="local-store")
    3. If neither found, raise 404
    """
    # Try Soroban first
    try:
        audit_data = get_audit_from_soroban(contract_hash)
        return VerifyResponse(
            contract_hash=audit_data["contract_hash"],
            report_hash=audit_data["report_hash"],
            risk_score=audit_data["risk_score"],
            ipfs_cid=audit_data["ipfs_cid"],
            timestamp=str(audit_data["timestamp"]),
            auditor=audit_data["auditor"],
            source="stellar"
        )
    except RuntimeError:
        # Fallback to local store
        history = get_history(contract_hash)
        if not history:
            raise HTTPException(
                status_code=404,
                detail="Audit record not found"
            )
        
        # Return most recent record
        most_recent = sorted(history, key=lambda x: x["created_at"], reverse=True)[0]
        return VerifyResponse(
            contract_hash=most_recent["contract_hash"],
            report_hash=most_recent["report_hash"],
            risk_score=most_recent["risk_score"],
            ipfs_cid=most_recent.get("ipfs_cid", ""),
            timestamp=most_recent["created_at"],
            auditor=most_recent["auditor"],
            source="local-store"
        )


@router.get("/history/{contract_hash}", response_model=List[HistoryRecord])
async def history(contract_hash: str):
    """
    Get audit history for a contract.
    
    Returns all records sorted by created_at descending.
    Returns empty list (not 404) when no records exist.
    """
    records = get_history(contract_hash)
    
    # Sort by created_at descending
    sorted_records = sorted(records, key=lambda x: x["created_at"], reverse=True)
    
    # Convert to HistoryRecord schema
    return [
        HistoryRecord(
            contract_hash=record["contract_hash"],
            report_hash=record["report_hash"],
            risk_score=record["risk_score"],
            ipfs_cid=record.get("ipfs_cid"),
            auditor=record["auditor"],
            created_at=record["created_at"],
            source=record.get("source", "local-store")
        )
        for record in sorted_records
    ]
