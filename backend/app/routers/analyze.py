from fastapi import APIRouter, HTTPException
from app.models.schemas import AnalyzeRequest, AnalyzeWithPdfResponse
from app.services.analyzer import analyze_contract
from app.services.report_generator import generate_audit_report
from app.services.ipfs_uploader import upload_pdf_to_ipfs
import json

router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"]
)

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
        analysis = analyze_contract(request.contract_code)
        pdf_path = generate_audit_report(analysis)
        ipfs = upload_pdf_to_ipfs(pdf_path)
        return {
            "analysis": analysis,
            "pdf_url": ipfs["url"],
            "cid": ipfs["cid"],
        }
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="AI returned invalid response. Please try again."
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )