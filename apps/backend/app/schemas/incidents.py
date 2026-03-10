"""
SOC-CyBe Security Platform
Module: Incident Response Schemas

Purpose:
These models define the API contracts for incident tickets, workflow updates,
timeline activities, and investigation dashboard summaries.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    """Payload used to create a new incident ticket."""
    title: str = Field(min_length=5, max_length=160)
    description: str = Field(min_length=10, max_length=1500)
    severity: Literal["Low", "Medium", "High", "Critical"]
    affected_asset: str = Field(min_length=2, max_length=120)


class IncidentUpdate(BaseModel):
    """Workflow update payload used by responders during an investigation."""
    status: Literal["Open", "Investigating", "Contained", "Resolved", "Closed"] | None = None
    response_stage: Literal[
        "Identification",
        "Containment",
        "Eradication",
        "Recovery",
        "Lessons Learned",
    ] | None = None
    notes: str = Field(min_length=4, max_length=1500)


class IncidentActivityItem(BaseModel):
    """Single incident timeline entry returned to analysts."""
    id: str
    activity_type: str
    notes: str
    created_at: datetime


class IncidentResponse(BaseModel):
    """Canonical incident representation returned by the API."""
    id: str
    title: str
    severity: str
    status: str
    response_stage: str
    affected_asset: str
    owner_user_id: str | None
    created_at: datetime
    updated_at: datetime


class InvestigationDashboardResponse(BaseModel):
    """Summary metrics for the incident investigation dashboard."""
    open_incidents: int
    critical_incidents: int
    containment_stage: int
    mean_time_to_contain_minutes: int
    active_tickets: list[IncidentResponse]
