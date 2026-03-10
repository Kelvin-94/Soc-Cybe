"""
SOC-CyBe Security Platform
Module: Compliance Schemas

Purpose:
These schemas define the contracts for consent capture, retention review,
and compliance reporting endpoints.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class ConsentRequest(BaseModel):
    """Request body used to record a privacy or data-use consent decision."""
    consent_type: str = Field(min_length=3, max_length=64)
    consent_granted: bool
    policy_version: str = Field(min_length=3, max_length=32)


class ConsentRecordResponse(BaseModel):
    """Stored consent record returned by compliance endpoints."""
    id: str
    user_id: str
    consent_type: str
    consent_granted: bool
    policy_version: str
    captured_at: datetime


class RetentionPolicyResponse(BaseModel):
    """Retention policy metadata exposed for audit review."""
    id: str
    data_domain: str
    retention_days: int
    legal_basis: str
    purge_strategy: str


class ComplianceReportResponse(BaseModel):
    """High-level compliance posture report for auditors and administrators."""
    generated_at: datetime
    frameworks: list[str]
    total_audit_logs: int
    audit_logs_last_30_days: int
    consent_records: int
    active_retention_policies: int
    data_deletion_ready: bool
    encryption_controls: list[str]
