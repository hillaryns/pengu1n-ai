from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.scan import router as scan_router
from app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
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