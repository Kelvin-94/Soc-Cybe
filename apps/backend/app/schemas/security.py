"""
SOC-CyBe Security Platform
Module: Security Schemas

Purpose:
Pydantic models in this file define the API contracts for authentication,
session identity, audit records, and request-level risk decisions.

Security Considerations:
- Strong typing here reduces malformed input risk and makes API expectations
  easier to audit.
- Authentication and session fields are explicit so downstream modules do not
  need to guess what trust context is available.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Credentials and client context supplied during login."""
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    ip_address: str
    device_id: str


class TokenResponse(BaseModel):
    """JWT response returned after successful authentication."""
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class AuthenticatedUser(BaseModel):
    """Trusted request context derived from the token, session, and database."""
    user_id: str
    tenant_id: str | None
    email: EmailStr
    role: str
    risk_score: int
    device_trust: int
    permissions: list[str]
    session_id: str
    session_status: str
    zero_trust_decision: str
    request_risk_score: int


class AuditLogEntry(BaseModel):
    """Normalized audit event returned by API log endpoints."""
    timestamp: datetime
    user_id: str
    ip_address: str
    endpoint: str
    action: str
    status: str


class SessionItem(BaseModel):
    """Session view exposed to analysts and administrators."""
    session_id: str
    user_id: str
    ip_address: str
    device_id: str | None
    status: str
    last_seen: datetime


class RiskEvaluation(BaseModel):
    """Risk decision returned by the risk inspection endpoint."""
    user_id: str
    session_id: str
    risk_score: int
    decision: Literal["allow", "step-up-authentication", "deny"]
    factors: dict[str, int | str | bool]
