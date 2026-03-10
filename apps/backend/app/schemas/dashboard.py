"""
SOC-CyBe Security Platform
Module: Dashboard Schemas

Purpose:
These models describe the structured dashboard data returned to the frontend.
They keep the visualization layer predictable while the backend evolves.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ThreatMetric(BaseModel):
    """Top-line dashboard metric shown in the SOC overview."""
    label: str
    value: int
    change: float


class AlertItem(BaseModel):
    """Alert row displayed in the dashboard feed."""
    id: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    title: str
    source: str
    timestamp: datetime
    status: str


class IncidentItem(BaseModel):
    """Incident summary card used by the dashboard."""
    id: str
    title: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    owner: str
    status: str
    response_stage: str


class DeviceItem(BaseModel):
    """Monitored device summary shown in the dashboard."""
    device_id: str
    device_type: str
    ip_address: str
    location: str
    risk_score: int
    status: str


class DashboardResponse(BaseModel):
    """Combined dashboard payload for the main SOC view."""
    metrics: list[ThreatMetric]
    alerts: list[AlertItem]
    incidents: list[IncidentItem]
    devices: list[DeviceItem]
