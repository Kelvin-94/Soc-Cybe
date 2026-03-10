"""
SOC-CyBe Security Platform
Module: Threat Analysis Schemas

Purpose:
These models describe threat-analysis and event-feed responses used by the SOC
dashboard and analyst workflows.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ThreatEventItem(BaseModel):
    """Single threat event entry for analyst review."""
    id: str
    event_type: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    source: str
    created_at: datetime
    summary: str


class ThreatAnalysisResponse(BaseModel):
    """Aggregated threat-analysis summary over a recent time window."""
    suspicious_logins: int
    abnormal_behaviors: int
    escalations: int
    alert_volume: int
    top_sources: list[dict[str, int | str]]
    recent_events: list[ThreatEventItem]
