"""
SOC-CyBe Security Platform
Module: Operational Extension Schemas

Purpose:
This file defines API contracts for the extended SOC modules: rule management,
threat intelligence, case management, playbooks, posture, simulations,
tenancy, and data deletion workflows.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class TenantResponse(BaseModel):
    """Tenant details returned to authenticated users."""
    id: str
    organization_id: str
    name: str
    status: str


class DetectionRuleCreate(BaseModel):
    """Payload used to create a new detection rule in the rule library."""
    rule_name: str = Field(min_length=4, max_length=160)
    event_conditions: dict
    severity_level: Literal["Low", "Medium", "High", "Critical"]
    response_action: str = Field(min_length=3, max_length=160)
    tactic: str | None = None
    technique: str | None = None
    mitre_technique_id: str | None = None


class DetectionRuleResponse(BaseModel):
    """Detection rule view including MITRE mapping data."""
    id: str
    rule_name: str
    severity_level: str
    response_action: str
    tactic: str | None
    technique: str | None
    mitre_technique_id: str | None
    is_active: bool


class RuleTestRequest(BaseModel):
    """Sandbox input used to test whether a rule would fire."""
    event_payload: dict


class RuleTestResponse(BaseModel):
    """Result of executing a detection rule against sandbox input."""
    matched: bool
    severity: str | None
    response_action: str | None


class ThreatIntelCreate(BaseModel):
    """Payload used to add a new threat intelligence indicator."""
    indicator_type: Literal["ip", "domain", "url", "hash"]
    indicator_value: str = Field(min_length=3, max_length=255)
    provider: str = Field(min_length=2, max_length=128)
    confidence: int = Field(ge=0, le=100)


class ThreatIntelResponse(BaseModel):
    """Threat intelligence indicator record returned by the API."""
    id: str
    indicator_type: str
    indicator_value: str
    provider: str
    confidence: int
    status: str


class CaseCreate(BaseModel):
    """Payload used to open a structured investigation case."""
    incident_reference: str | None = None
    assigned_analyst: str | None = None
    investigation_notes: str = Field(min_length=3, max_length=2000)
    evidence_files: list[str] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    """Payload used to progress or document an investigation case."""
    investigation_notes: str = Field(min_length=3, max_length=2000)
    status: Literal["Open", "Investigating", "Escalated", "Resolved", "Closed"] | None = None
    resolution_summary: str | None = Field(default=None, max_length=2000)


class CaseResponse(BaseModel):
    """Case record returned to analysts."""
    id: str
    incident_reference: str | None
    assigned_analyst: str | None
    investigation_notes: str
    evidence_files: list
    status: str
    resolution_summary: str | None
    updated_at: datetime


class PlaybookCreate(BaseModel):
    """Payload used to define a response playbook."""
    name: str = Field(min_length=4, max_length=160)
    trigger_event: str = Field(min_length=3, max_length=128)
    steps: list[dict] = Field(default_factory=list)
    requires_approval: bool = True


class PlaybookResponse(BaseModel):
    """Playbook configuration returned by the API."""
    id: str
    name: str
    trigger_event: str
    steps: list
    requires_approval: bool
    is_active: bool


class PlaybookExecutionResponse(BaseModel):
    """Execution summary for a SOAR-style playbook run."""
    playbook_id: str
    trigger_event: str
    execution_mode: Literal["automated", "awaiting-approval"]
    executed_steps: list[str]


class PostureSnapshotCreate(BaseModel):
    """Payload used to publish a new security posture snapshot."""
    environment_name: str = Field(min_length=3, max_length=128)
    patch_status: int = Field(ge=0, le=100)
    vulnerable_software: int = Field(ge=0)
    inactive_security_controls: int = Field(ge=0)
    unsecured_services: int = Field(ge=0)


class PostureSnapshotResponse(BaseModel):
    """Security posture snapshot returned to operators."""
    id: str
    environment_name: str
    patch_status: int
    vulnerable_software: int
    inactive_security_controls: int
    unsecured_services: int
    posture_score: int
    created_at: datetime


class CorrelationResponse(BaseModel):
    """Correlated event bundle returned by the SIEM correlation engine."""
    id: str
    correlation_name: str
    event_ids: list
    incident_id: str | None
    severity: str
    created_at: datetime


class SimulationCreate(BaseModel):
    """Payload used to execute or schedule a safe attack simulation scenario."""
    scenario_name: str = Field(min_length=4, max_length=160)
    scenario_type: Literal[
        "brute_force",
        "suspicious_login_location",
        "privilege_escalation",
        "malicious_file_execution",
        "data_exfiltration",
    ]
    mode: Literal["manual", "scheduled", "randomized"] = "manual"
    target_user: str | None = None
    target_device: str | None = None
    intensity_level: Literal["Low", "Medium", "High"] = "Medium"
    duration_minutes: int = Field(default=5, ge=1, le=120)
    training_mode: bool = False
    scheduled_for: datetime | None = None
    expected_detection: str = Field(min_length=6, max_length=1500)


class SimulationResponse(BaseModel):
    """Simulation record returned to analysts and trainers."""
    id: str
    scenario_name: str
    scenario_type: str
    mode: str
    intensity_level: str
    duration_minutes: int
    target_user: str | None
    target_device: str | None
    training_mode: bool
    scheduled_for: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    status: str
    safety_status: str
    safety_notes: str
    expected_detection: str
    scenario_config: dict
    detection_summary: dict
    timeline: list[dict]


class SimulationControlResponse(BaseModel):
    """Result returned when a simulation is started or stopped."""
    simulation_id: str
    status: str
    message: str


class DeletionRequest(BaseModel):
    """Request to mark a user's tenant-scoped data for deletion handling."""
    user_id: str


class DeletionResponse(BaseModel):
    """Result of a data deletion control action."""
    user_id: str
    tenant_id: str | None
    status: str
