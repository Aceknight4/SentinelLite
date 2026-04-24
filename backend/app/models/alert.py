# ============================================
# File    : alert.py
# Purpose : Alert database table definition
#           Each class = one database table
#           Each attribute = one column
# ============================================

from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from ..core.database import Base

class Alert(Base):
    """
    Represents one security alert in the database.

    __tablename__ tells SQLAlchemy which table
    to use in PostgreSQL.

    Every column has a type — SQLAlchemy translates
    Python types to PostgreSQL types automatically:
    Integer → INTEGER
    String  → VARCHAR
    Text    → TEXT
    DateTime→ TIMESTAMP
    Float   → FLOAT
    """
    __tablename__ = "alerts"

    # Primary key — auto-incrementing unique ID
    id = Column(Integer, primary_key=True, index=True)

    # When the alert was created
    # server_default=func.now() sets it automatically
    timestamp = Column(DateTime, server_default=func.now())

    # Severity level: low, medium, high, critical
    severity = Column(String(20), nullable=False, index=True)

    # Alert category: brute_force, port_scan, malware etc.
    category = Column(String(50), nullable=False)

    # Source IP that triggered the alert
    source_ip = Column(String(45))  # 45 chars handles IPv6

    # Destination IP
    dest_ip = Column(String(45))

    # Network port involved
    dest_port = Column(Integer)

    # Protocol: TCP, UDP, ICMP
    protocol = Column(String(10))

    # MITRE ATT&CK technique (e.g. T1110.003, T1078      
    mitre_technique = Column(String(20))

    # Human-readable description of the threat
    message = Column(Text, nullable=False)

    # Raw alert data from Suricata (JSON string)
    raw_data = Column(Text)

    # AI analysis result
    ai_analysis = Column(Text)

    # AI confidence score 0.0 to 1.0
    ai_confidence = Column(Float)

    # Status: new, reviewing, resolved, false_positive
    status = Column(String(20), default="new", index=True)

    # Which tenant this alert belongs to (for SaaS)
    tenant_id = Column(String(50), default="default", index=True)

    def __repr__(self):
        return f"<Alert {self.id}: {self.severity} - {self.category}>"
