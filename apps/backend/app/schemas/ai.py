"""
SOC-CyBe Security Platform
Module: AI Detection Schemas

Purpose:
These models describe the AI-driven anomaly detection API contracts, including
training requests, stored anomaly findings, and model scoring outputs.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class AITrainingRequest(BaseModel):
    tenant_id: str | None = None
    lookback_hours: int = Field(default=168, ge=1, le=2160)


class AITrainingResponse(BaseModel):
    trained: bool
    sample_count: int
    model_version: str
    lookback_hours: int


class AIScoreResponse(BaseModel):
    user_id: str
    risk_level: Literal["Low", "Moderate", "High", "Critical"]
    anomaly_type: str
    recommended_action: str
    risk_score: int
    confidence_score: int


class AIFindingResponse(BaseModel):
    id: str
    event_id: str | None
    anomaly_type: str
    confidence_score: int
    risk_score: int
    severity: str
    recommended_action: str
    device_id: str | None
    created_at: datetime
