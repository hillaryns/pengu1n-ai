from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import load_environment
from app.api.scan import router as scan_router
from app.db.database import init_db

# Load backend/.env before request handling so PENGU1N_API_KEYS is available.
load_environment()


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