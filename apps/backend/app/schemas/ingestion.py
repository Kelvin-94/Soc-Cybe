"""
SOC-CyBe Security Platform
Module: Ingestion Schemas

Purpose:
Contracts for event ingestion endpoints that accept raw telemetry, normalize it,
and return the processing outcome.
"""

from pydantic import BaseModel, Field


class IngestEventRequest(BaseModel):
    """Incoming telemetry payload submitted to the ingestion layer."""
    source_type: str = Field(min_length=3, max_length=64)
    payload: dict


class IngestEventResponse(BaseModel):
    """Normalized ingestion result including intel and correlation outcomes."""
    normalized_event: dict
    intel_matches: list[str]
    correlated_incident: str | None
