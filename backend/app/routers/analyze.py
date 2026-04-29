from fastapi import APIRouter, HTTPException
from app.models.schemas import AnalyzeRequest, AnalyzeResponse
from app.services.analyzer import analyze_contract
import json

router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"]
)

@router.post("/", response_model=AnalyzeResponse)
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
        result = analyze_contract(request.contract_code)
        return result
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