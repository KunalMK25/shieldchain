from fastapi import APIRouter

from app.models.schemas import AuditRecordResponse, RegisterAuditRequest
from app.services.audit_store import get_history, register_audit

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.post("/register", response_model=AuditRecordResponse)
async def register(request: RegisterAuditRequest):
    return register_audit(request.model_dump())


@router.get("/history/{contract_hash}", response_model=list[AuditRecordResponse])
async def history(contract_hash: str):
    return get_history(contract_hash)
