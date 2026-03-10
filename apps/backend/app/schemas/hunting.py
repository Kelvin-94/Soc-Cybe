"""
SOC-CyBe Security Platform
Module: Threat Hunting Schemas

Purpose:
These models define the API contracts for proactive threat-hunting workflows:
search queries, saved hunts, event timelines, investigation reports, and
conversion of hunt findings into alerts or incidents.

Security Notes:
- Hunt requests are strongly typed so analysts can build rich searches without
  relying on unsafe raw query syntax.
- Saved hunt artifacts are tenant-scoped because investigative hypotheses and
  evidence should not cross organizational boundaries.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ThreatHuntSearchRequest(BaseModel):
    """Flexible threat-hunting query over stored security events."""
    username: str | None = None
    ip_address: str | None = None
    device_id: str | None = None
    event_type: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    min_risk_score: int | None = Field(default=None, ge=0, le=100)
    query_text: str | None = Field(default=None, max_length=255)
    limit: int = Field(default=50, ge=1, le=200)


class ThreatHuntResultItem(BaseModel):
    """Single event returned by the hunting engine."""
    event_id: str
    event_type: str
    severity: str
    source: str
    username: str | None
    ip_address: str | None
    device_id: str | None
    created_at: datetime
    risk_score: int
    summary: str
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_technique_id: str | None
    intel_matches: list[str]


class ThreatHuntTimelineItem(BaseModel):
    """Timeline entry used to reconstruct suspicious behavior."""
    timestamp: datetime
    event_id: str
    event_type: str
    description: str
    source: str


class ThreatHuntSearchResponse(BaseModel):
    """Structured response returned after running a hunt query."""
    query_summary: str
    total_results: int
    results: list[ThreatHuntResultItem]
    timeline: list[ThreatHuntTimelineItem]
    behavioral_patterns: list[str]
    ai_suggestions: list[str]


class SavedThreatHuntCreate(BaseModel):
    """Payload used to store a reusable hunt query."""
    name: str = Field(min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=600)
    filters: dict
    notes: str | None = Field(default=None, max_length=2000)


class SavedThreatHuntResponse(BaseModel):
    """Saved hunt definition returned to analysts."""
    id: str
    name: str
    description: str | None
    filters: dict
    notes: str | None
    created_at: datetime
    updated_at: datetime


class ThreatHuntReportCreate(BaseModel):
    """Payload used to generate a reusable hunt report."""
    title: str = Field(min_length=4, max_length=160)
    summary: str = Field(min_length=10, max_length=2500)
    events_analyzed: int = Field(ge=0)
    identified_threats: list[str] = Field(default_factory=list)
    recommended_mitigations: list[str] = Field(default_factory=list)
    query_id: str | None = None
    export_format: Literal["json", "markdown"] = "json"


class ThreatHuntReportResponse(BaseModel):
    """Threat-hunting report returned by the API."""
    id: str
    title: str
    summary: str
    events_analyzed: int
    identified_threats: list[str]
    recommended_mitigations: list[str]
    export_format: str
    created_at: datetime


class ThreatHuntPromoteRequest(BaseModel):
    """Payload used to convert hunt findings into formal response artifacts."""
    title: str = Field(min_length=4, max_length=160)
    description: str = Field(min_length=10, max_length=2000)
    severity: Literal["Low", "Medium", "High", "Critical"]
    affected_asset: str = Field(min_length=2, max_length=120)
    evidence_event_ids: list[str] = Field(default_factory=list)


class ThreatHuntPromoteResponse(BaseModel):
    """Response returned after promoting hunt findings into action."""
    alert_id: str
    incident_id: str
    case_id: str
    status: str
