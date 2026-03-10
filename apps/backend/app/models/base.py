"""
SOC-CyBe Security Platform
Module: SQLAlchemy Declarative Base

Purpose:
This module defines the declarative base class used by all ORM models.
Keeping it isolated avoids circular imports and gives the backend one clear
metadata registry for table creation and migrations.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for every persisted SOC-CyBe entity."""
    pass
