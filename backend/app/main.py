import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.core.config import settings
from app.core.logging import logger
from app.database.mongodb import db_manager

# API Routers
from app.api.analyze import router as analyze_router
from app.api.auth import router as auth_router
from app.api.history import router as history_router
from app.api.reports import router as reports_router
from app.api.samples import router as samples_router

from app.detection.threat_intel.dataset_feed import LocalThreatIntelligenceFeed


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Cyber Shield Engine Services...")
    await db_manager.connect_db()
    # Pre-index threat intelligence database
    LocalThreatIntelligenceFeed.initialize()
    yield
    logger.info("Shutting down Cyber Shield Services...")
    await db_manager.close_db()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Privacy-First Cybersecurity Detection & Explainable Threat Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routes
app.include_router(analyze_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(history_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(samples_router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "in_memory" if db_manager.use_in_memory else "mongodb"
    }


# Production Static React Frontend Integration
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if not os.path.exists(frontend_dist):
    frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))

if os.path.exists(frontend_dist) and os.path.exists(os.path.join(frontend_dist, "index.html")):
    assets_dir = os.path.join(frontend_dist, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        if full_path.startswith("api/") or full_path == "api":
            return {"error": "API route not found"}
        target = os.path.join(frontend_dist, full_path)
        if os.path.isfile(target):
            return FileResponse(target)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    async def root():
        return {
            "status": "active",
            "service": "Cyber Shield Detection Gateway",
            "engines": ["rules", "nlp", "threat_intelligence", "behavior"],
            "docs_url": "/docs"
        }
