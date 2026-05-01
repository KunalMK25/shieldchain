from fastapi import APIRouter, HTTPException
from app.models.schemas import AnalyzeRequest, AnalyzeWithPdfResponse, AuditBounds
from app.services.analyzer import analyze_contract
from app.services.report_generator import generate_audit_report
from app.services.ipfs_uploader import upload_pdf_to_ipfs
from app.services.hash_utils import generate_contract_and_pdf_hashes
from app.services.dynamic_analyzer import run_dynamic_analysis
from app.services.sentinel import SentinelMonitor, active_monitors
import asyncio
import hashlib
import json
import logging
import glob
import os
from pathlib import Path

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"]
)

# Toggle between agent-based and simple analysis
USE_AGENTS = os.getenv("USE_LANGCHAIN_AGENTS", "false").lower() == "true"

# Conditional import of agents
_agents_available = False
if USE_AGENTS:
    try:
        from app.services.agents import run_full_analysis
        _agents_available = True
        logger.info("LangChain agents loaded — will run as background enrichment")
    except ImportError as e:
        logger.warning(f"Failed to load LangChain agents: {e}. Falling back to simple analysis.")


async def _run_agents_background(contract_code: str, contract_name: str, contract_hash: str):
    """Run agents in background after response is returned — non-blocking."""
    try:
        from app.services.agents import run_full_analysis
        logger.info(f"[AGENTS] Starting background agent analysis for {contract_hash[:8]}")
        result = await run_full_analysis(contract_code=contract_code, contract_name=contract_name)
        logger.info(f"[AGENTS] Background analysis complete — risk_score={result.get('risk_score')}")
    except Exception as e:
        logger.error(f"[AGENTS] Background agent analysis failed: {e}")

@router.post("/", response_model=AnalyzeWithPdfResponse)
async def analyze(request: AnalyzeRequest):
    if not request.contract_code.strip():
        raise HTTPException(
            status_code=400,
            detail="Contract code cannot be empty"
        )

    if len(request.contract_code) > 50000:
        raise HTTPException(
            status_code=400,
            detail="Contract code too large. Maximum 50,000 characters."
        )

    try:
        # Step 1: Static analysis — always use fast analyzer for immediate response
        logger.info("Running fast static analysis")
        analysis = analyze_contract(request.contract_code)

        # Fire agents in background if available (non-blocking, enriches logs only)
        contract_hash = hashlib.sha256(request.contract_code.encode("utf-8")).hexdigest()
        if USE_AGENTS and _agents_available:
            asyncio.create_task(_run_agents_background(
                contract_code=request.contract_code,
                contract_name=request.contract_name or "Unknown Contract",
                contract_hash=contract_hash
            ))
        
        # Step 3: Launch dynamic analysis asynchronously (non-blocking)
        dynamic_task = asyncio.create_task(
            run_dynamic_analysis(
                contract_code=request.contract_code,
                contract_name=request.contract_name or "Unknown Contract",
                contract_hash=contract_hash
            )
        )
        
        # Step 4: Await dynamic analysis with 90-second timeout
        dynamic_result = None
        dynamic_status = None
        
        try:
            dynamic_result = await asyncio.wait_for(dynamic_task, timeout=90.0)
            dynamic_status = dynamic_result.dynamic_status
            logger.info(
                f"Dynamic analysis completed for {contract_hash}: "
                f"status={dynamic_status}, anomalies={dynamic_result.anomalies_found}"
            )
        except asyncio.TimeoutError:
            logger.warning(f"Dynamic analysis timed out for {contract_hash}")
            dynamic_status = "TIMEOUT"
        except Exception as e:
            logger.error(
                f"Dynamic analysis failed for {contract_hash}: {e}",
                exc_info=True
            )
            dynamic_status = "DEPLOY_FAILED"
        
        # Step 5: Merge dynamic results into analysis response
        merged_result = {
            "analysis": analysis,
            "contract_hash": contract_hash,
        }
        
        if dynamic_result and dynamic_result.dynamic_status == "OK":
            # Merge successful dynamic results
            merged_result.update({
                "contract_id": dynamic_result.contract_id,
                "dynamic_audit_log": dynamic_result.dynamic_audit_log,
                "anomalies_found": dynamic_result.anomalies_found,
                "dynamic_risk_adjustment": dynamic_result.dynamic_risk_adjustment,
                "dynamic_status": dynamic_result.dynamic_status,
            })
            
            # Step 5.1: Create SentinelMonitor for continuous monitoring
            # Only create if dynamic analysis succeeded and we have a contract_id
            if dynamic_result.contract_id and contract_hash not in active_monitors:
                try:
                    # Extract expected functions from dynamic audit log
                    expected_functions = list(set(
                        entry.function_called 
                        for entry in dynamic_result.dynamic_audit_log
                    )) if dynamic_result.dynamic_audit_log else []
                    
                    # Create audit bounds based on analysis results
                    audit_bounds = AuditBounds(
                        max_param_value=1000000,  # Default reasonable limit
                        expected_functions=expected_functions,
                        risk_score=analysis.get("risk_score", 0)  # Include static risk score
                    )
                    
                    # Create and register the monitor
                    monitor = SentinelMonitor(
                        audit_bounds=audit_bounds,
                        contract_id=dynamic_result.contract_id,
                        contract_hash=contract_hash
                    )
                    
                    active_monitors[contract_hash] = monitor
                    
                    # Start monitoring in background (non-blocking)
                    asyncio.create_task(monitor.start_monitoring())
                    
                    logger.info(
                        f"Created SentinelMonitor for contract {contract_hash} "
                        f"with {len(expected_functions)} expected functions"
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to create SentinelMonitor for {contract_hash}: {e}",
                        exc_info=True
                    )
                    # Don't fail the entire request if sentinel creation fails
        elif dynamic_result:
            # Merge partial dynamic results (with failure status)
            merged_result.update({
                "contract_id": dynamic_result.contract_id,
                "dynamic_audit_log": dynamic_result.dynamic_audit_log,
                "anomalies_found": dynamic_result.anomalies_found,
                "dynamic_risk_adjustment": dynamic_result.dynamic_risk_adjustment,
                "dynamic_status": dynamic_result.dynamic_status,
            })
        else:
            # No dynamic result (timeout or exception)
            merged_result.update({
                "contract_id": None,
                "dynamic_audit_log": None,
                "anomalies_found": None,
                "dynamic_risk_adjustment": None,
                "dynamic_status": dynamic_status,
            })
        
        # Step 6: Re-generate PDF with dynamic results when available
        # Prepare the complete data for PDF generation
        pdf_data = {
            **analysis,  # Spread the analysis data (risk_score, vulnerabilities, etc.)
            "contract_id": merged_result.get("contract_id"),
            "dynamic_audit_log": merged_result.get("dynamic_audit_log"),
            "anomalies_found": merged_result.get("anomalies_found"),
            "dynamic_risk_adjustment": merged_result.get("dynamic_risk_adjustment"),
            "dynamic_status": merged_result.get("dynamic_status"),
        }
        
        pdf_path, report_id = generate_audit_report(
            pdf_data,
            contract_name=request.contract_name
        )
        
        # Step 7: Upload PDF to IPFS
        ipfs = upload_pdf_to_ipfs(pdf_path)
        
        # Step 8: Generate final hashes (including PDF hash)
        final_hashes = generate_contract_and_pdf_hashes(request.contract_code, pdf_path)
        
        # Step 9: Return merged response with all fields
        return {
            "analysis": analysis,
            "pdf_url": ipfs["url"],
            "cid": ipfs["cid"],
            "report_id": report_id,
            "contract_hash": final_hashes["contract_hash"],
            "contract_id": merged_result.get("contract_id"),
            "dynamic_audit_log": merged_result.get("dynamic_audit_log"),
            "anomalies_found": merged_result.get("anomalies_found"),
            "dynamic_risk_adjustment": merged_result.get("dynamic_risk_adjustment"),
            "dynamic_status": merged_result.get("dynamic_status"),
        }
        
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="AI returned invalid response. Please try again."
        )
    except Exception as e:
        # Note: Dynamic analysis failures are handled above and never reach here
        # This only catches static analysis failures
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get("/logs")
async def get_audit_logs():
    """
    Returns all audit logs from LangChain agent executions.
    Shows judges the dynamic analysis trail with full chain-of-thought.
    """
    try:
        log_dir = Path(__file__).resolve().parents[1] / "logs"
        log_files = glob.glob(str(log_dir / "audit_*.json"))
        
        logs = []
        for f in sorted(log_files, reverse=True)[:10]:  # Last 10 audits
            try:
                with open(f, 'r') as file:
                    logs.append(json.load(file))
            except Exception as e:
                logger.error(f"Failed to read log file {f}: {e}")
        
        return {
            "logs": logs,
            "total": len(log_files),
            "message": "Showing last 10 audit trails"
        }
    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {e}")
        return {
            "logs": [],
            "total": 0,
            "error": str(e)
        }

