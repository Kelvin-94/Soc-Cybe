"""
SOC-CyBe Security Platform
Module: Database Session Management

Purpose:
This module creates the SQLAlchemy engine and request-scoped database session
dependency used by FastAPI routes and backend services.

Security Considerations:
- Database connectivity is centralized so TLS, credentials, and connection
  behavior can be controlled consistently.
- Sessions are short-lived and explicitly closed, which helps avoid stale
  transactions and accidental data leakage across requests.

Related Components:
- `app/core/config.py` for connection strings
- `app/main.py` for metadata creation on startup
- all API and service modules that depend on persistent state
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """
    Yield a request-scoped database session to FastAPI dependencies.

    Each request gets its own session so transaction boundaries are clear and
    one caller cannot accidentally affect another caller's data context.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
