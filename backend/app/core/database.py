# ============================================
# File    : database.py
# Purpose : PostgreSQL connection via SQLAlchemy
# ============================================

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import get_settings

settings = get_settings()

# create_engine() creates the connection pool
# pool_pre_ping=True checks connection health
# before each use — handles dropped connections
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True
)

# SessionLocal is a factory that creates
# database sessions — one per request
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base is the parent class for all database models
# Every table you create inherits from this
Base = declarative_base()

def get_db():
    """
    Dependency function for FastAPI endpoints.
    Creates a database session, yields it to
    the endpoint, then closes it automatically.

    'yield' makes this a generator — FastAPI
    calls next() to get the db session, then
    calls cleanup after the request finishes.
    This guarantees the session always closes
    even if an error occurs.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
