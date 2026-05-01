from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import analyze, report, blockchain, dynamic_analyze, sentinel
from app.routers import audit
from app.models.schemas import StatusResponse
from dotenv import load_dotenv
import os

load_dotenv('D:/shieldchain/.env')

app = FastAPI(
    title="ShieldChain API",
    description="AI-Powered Soroban Smart Contract Security Scanner",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(audit.router)
app.include_router(report.router)
app.include_router(blockchain.router)
app.include_router(dynamic_analyze.router)
app.include_router(sentinel.router)

@app.get("/")
async def root():
    return {
        "message": "ShieldChain API is running",
        "version": "1.0.0",
        "status": "healthy"
    }

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/status", response_model=StatusResponse)
async def status() -> StatusResponse:
    """
    Returns connectivity status for all external services.
    Checks presence of env vars; does NOT make live API calls.
    """
    groq_connected = bool(os.getenv("GROQ_API_KEY"))
    stellar_connected = bool(os.getenv("STELLAR_RPC_URL") and os.getenv("STELLAR_SECRET_KEY"))
    pinata_connected = bool(os.getenv("PINATA_API_KEY") and os.getenv("PINATA_SECRET_KEY"))
    dynamic_analysis_enabled = bool(os.getenv("STELLAR_PUBLIC_KEY") and os.getenv("STELLAR_SECRET_KEY"))
    
    endpoints = [route.path for route in app.routes]
    
    return StatusResponse(
        api_status="ok",
        version="1.0.0",
        endpoints=endpoints,
        groq_connected=groq_connected,
        stellar_connected=stellar_connected,
        pinata_connected=pinata_connected,
        dynamic_analysis_enabled=dynamic_analysis_enabled
    )