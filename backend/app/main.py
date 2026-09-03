from contextlib import asynccontextmanager
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import load_environment
from app.api.scan import router as scan_router
from app.db.database import init_db

# Load backend/.env before request handling so PENGU1N_API_KEYS is available.
load_environment()


def _cors_origins() -> list[str]:
    raw_value = os.getenv(
        "PENGU1N_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    return [origin.strip() for origin in raw_value.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_environment()
    init_db()
    yield


app = FastAPI(
    title="Pengu1n AI",
    description="AI-powered cybersecurity scanner for authorized security assessments.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)


@app.get("/")
def root():
    return {
        "name": "Pengu1n AI",
        "status": "online",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
