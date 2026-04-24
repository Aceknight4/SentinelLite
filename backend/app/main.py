# ============================================
# File    : main.py
# Purpose : FastAPI application entry point
#           Registers all routes and middleware
# ============================================

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .core.database import engine, get_db, Base
from .core.config import get_settings
from .api.routes import alerts
from .models.schemas import HealthResponse

# Create all database tables on startup
# If tables already exist — no error, just skipped
Base.metadata.create_all(bind=engine)

settings = get_settings()

# Create the FastAPI application
app = FastAPI(
    title="SentinelLite SOC Platform",
    description="Cloud-Based SOC Automation Platform",
    version="1.0.0",
    docs_url="/docs",      # Swagger UI at /docs
    redoc_url="/redoc"     # ReDoc UI at /redoc
)

# CORS middleware allows the frontend (different port)
# to call the API. Without this, browsers block requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # In production: specify exact domains
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route groups
# All alert routes will be at /api/v1/alerts/...
app.include_router(
    alerts.router,
    prefix=f"/api/{settings.api_version}"
)

@app.get("/", tags=["Root"])
def root():
    """Root endpoint — confirms server is running."""
    return {
        "platform": "SentinelLite",
        "status"  : "running",
        "docs"    : "/docs"
    }

@app.get("/api/health", response_model=HealthResponse,
         tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint.
    Tests database connectivity.
    Used by monitoring tools and load balancers.
    """
    try:
        db.execute(__import__('sqlalchemy').text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version="1.0.0",
        database=db_status
    )
