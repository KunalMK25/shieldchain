"""
Report generation and download router.

Provides endpoints for generating PDF audit reports and downloading them.
"""

from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.models.schemas import GenerateReportRequest, GenerateReportResponse
from app.services.report_generator import generate_audit_report
from app.services.ipfs_uploader import upload_pdf_to_ipfs


router = APIRouter(prefix="/report", tags=["Report"])


@router.post("/generate", response_model=GenerateReportResponse)
async def generate_report(request: GenerateReportRequest) -> GenerateReportResponse:
    """
    Generate a PDF audit report and upload it to IPFS.
    
    Steps:
    1. Generate PDF report from analysis data
    2. Upload PDF to IPFS via Pinata
    3. Return IPFS CID, URL, report ID, and download URL
    
    Args:
        request: GenerateReportRequest containing analysis data and contract name
    
    Returns:
        GenerateReportResponse with CID, PDF URL, report ID, and download URL
    
    Raises:
        HTTPException 422: Invalid analysis data (Pydantic validation)
        HTTPException 502: IPFS upload failure
    """
    try:
        # Step 1: Generate PDF report
        pdf_path, report_id = generate_audit_report(
            analysis_response=request.analysis.model_dump(),
            contract_name=request.contract_name or "Unknown Contract"
        )
        
        # Step 2: Upload PDF to IPFS
        try:
            ipfs_result = upload_pdf_to_ipfs(pdf_path)
            cid = ipfs_result["cid"]
            pdf_url = ipfs_result["url"]
        except RuntimeError as e:
            # IPFS upload failed - raise HTTP 502
            raise HTTPException(
                status_code=502,
                detail=f"IPFS upload failed: {str(e)}"
            )
        
        # Step 3: Return response with download URL
        download_url = f"/report/download/{report_id}"
        
        return GenerateReportResponse(
            cid=cid,
            pdf_url=pdf_url,
            report_id=report_id,
            download_url=download_url
        )
    
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Catch any other unexpected errors
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {str(e)}"
        )


@router.get("/download/{report_id}")
async def download_report(report_id: str) -> FileResponse:
    """
    Download a generated PDF audit report by report ID.
    
    Args:
        report_id: The timestamp-based report ID (e.g., "20260429_204933")
    
    Returns:
        FileResponse with the PDF file
    
    Raises:
        HTTPException 404: Report file not found
    """
    # Resolve the PDF file path
    reports_dir = Path(__file__).resolve().parents[2] / "reports"
    filename = f"shieldchain_audit_{report_id}.pdf"
    pdf_path = reports_dir / filename
    
    # Check if file exists
    if not pdf_path.exists() or not pdf_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Report not found: {report_id}"
        )
    
    # Return the PDF file
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=filename
    )
