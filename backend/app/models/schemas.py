# ============================================
# File    : schemas.py
# Purpose : Pydantic schemas for API validation
#           Schema = shape of data in/out of API
# ============================================

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class AlertCreate(BaseModel):
    """
    Schema for creating a new alert.
    This is what Suricata sends to POST /alerts.

    Field(...) means required.
    Field("default") means optional with default.
    """
    severity: str = Field(..., description="low/medium/high/critical")
    category: str = Field(..., description="Alert category")
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    message: str = Field(..., description="Alert description")
    raw_data: Optional[str] = None
    tenant_id: str = Field("default")

class AlertResponse(BaseModel):
    """
    Schema for returning an alert from the API.
    This is what the dashboard receives.
    Includes all fields plus auto-generated ones.
    """
    id: int
    timestamp: datetime
    severity: str
    category: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    protocol: Optional[str]
    message: str
    ai_analysis: Optional[str]
    ai_confidence: Optional[float]
    status: str
    tenant_id: str

    class Config:
        # orm_mode tells Pydantic to read data from
        # SQLAlchemy model objects, not just dicts
        from_attributes = True

class AlertUpdate(BaseModel):
    """Schema for updating an alert status."""
    status: str
    ai_analysis: Optional[str] = None

class HealthResponse(BaseModel):
    """Schema for health check endpoint."""
    status: str
    version: str
    database: str
