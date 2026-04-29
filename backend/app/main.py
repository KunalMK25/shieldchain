from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import analyze, audit
from dotenv import load_dotenv

load_dotenv('../../.env')

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