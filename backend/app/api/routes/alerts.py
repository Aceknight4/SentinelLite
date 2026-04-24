# ============================================
# File    : alerts.py
# Purpose : Alert API endpoints
#           All routes for /api/alerts
# ============================================

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from ...core.database import get_db
from ...models.alert import Alert
from ...models.schemas import AlertCreate, AlertResponse, AlertUpdate

# APIRouter groups related endpoints together
# prefix means all routes start with /alerts
router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.post("/", response_model=AlertResponse, status_code=201)
def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    """
    Receive a new security alert.
    Called by Suricata or any detection system.

    Depends(get_db) is FastAPI dependency injection —
    FastAPI automatically creates a db session and
    passes it to this function. When the function
    finishes, FastAPI closes the session.
    """
    # Create SQLAlchemy model from Pydantic schema
    db_alert = Alert(**alert.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)  # reload to get auto-generated fields
    return db_alert

@router.get("/", response_model=List[AlertResponse])
def get_alerts(
    skip: int = Query(0, description="Skip N records"),
    limit: int = Query(50, description="Return max N records"),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    tenant_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    """
    Retrieve alerts with optional filtering.
    Supports pagination with skip/limit.
    """
    query = db.query(Alert).filter(Alert.tenant_id == tenant_id)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)

    # Order by most recent first
    query = query.order_by(Alert.timestamp.desc())

    return query.offset(skip).limit(limit).all()

@router.get("/stats")
def get_stats(tenant_id: str = Query("default"),
              db: Session = Depends(get_db)):
    """
    Returns alert statistics for the dashboard.
    """
    total   = db.query(Alert).filter(
        Alert.tenant_id == tenant_id).count()
    new     = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.status == "new").count()
    high    = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.severity == "high").count()
    critical = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.severity == "critical").count()

    return {
        "total"   : total,
        "new"     : new,
        "high"    : high,
        "critical": critical
    }

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Retrieve one specific alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        # HTTPException sends a proper HTTP error response
        # 404 = Not Found — standard HTTP status code
        raise HTTPException(status_code=404,
                           detail=f"Alert {alert_id} not found")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, update: AlertUpdate,
                 db: Session = Depends(get_db)):
    """Update an alert's status or AI analysis."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404,
                           detail=f"Alert {alert_id} not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(alert, field, value)

    db.commit()
    db.refresh(alert)
    return alert
