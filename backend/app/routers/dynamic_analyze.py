"""
Dynamic analysis router for ShieldChain.

Exposes POST /dynamic-analyze endpoint that deploys a Soroban contract
to Stellar Testnet and runs fuzzing transactions against it.
"""

from fastapi import APIRouter, HTTPException
from app.models.schemas import DynamicAnalyzeRequest, DynamicAnalyzeResponse
from app.services.dynamic_analyzer import run_dynamic_analysis
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/dynamic-analyze",
    tags=["Dynamic Analysis"]
)


@router.post("/", response_model=DynamicAnalyzeResponse)
async def dynamic_analyze(request: DynamicAnalyzeRequest) -> DynamicAnalyzeResponse:
    """
    Standalone dynamic analysis endpoint.
    
    Deploys a Soroban contract to Stellar Testnet, executes fuzzing transactions,
    collects Horizon logs, and classifies results with Groq AI.
    
    Args:
        request: DynamicAnalyzeRequest with contract_code, contract_name, contract_hash
    
    Returns:
        DynamicAnalyzeResponse with contract_id, dynamic_audit_log, anomalies_found,
        dynamic_risk_adjustment, and dynamic_status
    
    Note:
        Never returns HTTP 500 — all failures are encoded in dynamic_status field.
        Possible dynamic_status values:
        - "OK": Analysis completed successfully
        - "DEPLOY_FAILED": Compilation or deployment failed
        - "HORIZON_UNAVAILABLE": Horizon API unreachable
        - "TIMEOUT": Analysis exceeded 90-second timeout
    """
    if not request.contract_code.strip():
        # Return a valid response with DEPLOY_FAILED status instead of HTTP 400
        logger.warning("Empty contract code provided to dynamic_analyze")
        return DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="DEPLOY_FAILED"
        )
    
    try:
        # Run the full dynamic analysis pipeline
        result = await run_dynamic_analysis(
            contract_code=request.contract_code,
            contract_name=request.contract_name or "Unknown Contract",
            contract_hash=request.contract_hash
        )
        
        logger.info(
            f"Dynamic analysis completed for {request.contract_hash}: "
            f"status={result.dynamic_status}, anomalies={result.anomalies_found}"
        )
        
        return result
    
    except Exception as e:
        # Never return HTTP 500 — encode failure in dynamic_status
        logger.error(
            f"Dynamic analysis failed for {request.contract_hash}: {e}",
            exc_info=True
        )
        return DynamicAnalyzeResponse(
            contract_id=None,
            dynamic_audit_log=[],
            anomalies_found=0,
            dynamic_risk_adjustment=0,
            dynamic_status="DEPLOY_FAILED"
        )
