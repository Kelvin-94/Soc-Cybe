"""
SOC-CyBe Security Platform
Module: ORM Entities

Purpose:
This module defines the persistent entities used by the platform. The models
cover tenants, users, sessions, detections, incidents, cases, playbooks,
compliance records, posture snapshots, and related operational artifacts.

Security Considerations:
- Tenant-aware fields are included so organizations can be isolated logically.
- Sensitive operational fields use encrypted SQLAlchemy types where appropriate.
- Audit and detection entities are stored explicitly because investigators and
  auditors need durable evidence, not transient in-memory state.

Related Components:
- `app/api/routes.py` for API access
- `app/services/*` for SOC workflows
- `infrastructure/postgres/init.sql` for bootstrapped storage schema
"""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.types import EncryptedString
from app.models.base import Base


def uuid_str() -> str:
    """Generate string UUIDs for model primary keys."""
    return str(uuid4())


class Role(Base):
    """RBAC role definition used to grant groups of permissions to users."""
    __tablename__ = "soc_roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    permissions: Mapped[list["RolePermission"]] = relationship(back_populates="role", cascade="all, delete-orphan")
    users: Mapped[list["User"]] = relationship(back_populates="role")


class Tenant(Base):
    """Tenant record for multi-organization SOC deployments."""
    __tablename__ = "soc_tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    organization_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Permission(Base):
    """Named action that can be granted to a role."""
    __tablename__ = "soc_permissions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    roles: Mapped[list["RolePermission"]] = relationship(back_populates="permission", cascade="all, delete-orphan")


class RolePermission(Base):
    """Association table linking roles to permissions."""
    __tablename__ = "soc_role_permissions"

    role_id: Mapped[str] = mapped_column(ForeignKey("soc_roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[str] = mapped_column(
        ForeignKey("soc_permissions.id", ondelete="CASCADE"), primary_key=True
    )

    role: Mapped[Role] = relationship(back_populates="permissions")
    permission: Mapped[Permission] = relationship(back_populates="roles")


class User(Base):
    """Platform user account with tenant, role, and consent state."""
    __tablename__ = "soc_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    role_id: Mapped[str | None] = mapped_column(ForeignKey("soc_roles.id"))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    consent_logged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    role: Mapped[Role | None] = relationship(back_populates="users")
    sessions: Mapped[list["Session"]] = relationship(back_populates="user")
    risk_score: Mapped["RiskScore | None"] = relationship(back_populates="user", uselist=False)


class RiskScore(Base):
    """Per-user risk state used by the Zero Trust request path."""
    __tablename__ = "soc_risk_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("soc_users.id"), unique=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ip_reputation: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    device_trust: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    privilege_changes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="risk_score")


class SecurityEvent(Base):
    """Normalized security event stored for detection, correlation, and audit review."""
    __tablename__ = "soc_security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    event_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Alert(Base):
    """Analyst-facing alert produced by detections, intel matches, or correlations."""
    __tablename__ = "soc_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    event_id: Mapped[str | None] = mapped_column(ForeignKey("soc_security_events.id"))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Open")
    source: Mapped[str] = mapped_column(String(128), nullable=False, default="threat-monitor")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Incident(Base):
    """Formal incident ticket used for response management."""
    __tablename__ = "soc_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Open")
    response_stage: Mapped[str] = mapped_column(String(32), nullable=False, default="Identification")
    affected_asset: Mapped[str] = mapped_column(String(120), nullable=False)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class IncidentActivity(Base):
    """Timeline entries that document how an incident was investigated and handled."""
    __tablename__ = "soc_incident_activities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    incident_id: Mapped[str] = mapped_column(ForeignKey("soc_incidents.id", ondelete="CASCADE"), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    activity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class ConsentRecord(Base):
    """Privacy and consent evidence record for legal and regulatory review."""
    __tablename__ = "soc_consent_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("soc_users.id"), nullable=False)
    consent_type: Mapped[str] = mapped_column(String(64), nullable=False)
    consent_granted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="2026.03")
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class RetentionPolicy(Base):
    """Retention guidance for a class of security or privacy data."""
    __tablename__ = "soc_retention_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    data_domain: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    legal_basis: Mapped[str] = mapped_column(String(128), nullable=False)
    purge_strategy: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class DetectionRule(Base):
    """Detection library entry supporting rule logic and MITRE mapping."""
    __tablename__ = "soc_detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    rule_name: Mapped[str] = mapped_column(String(160), nullable=False)
    event_conditions: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    severity_level: Mapped[str] = mapped_column(String(16), nullable=False)
    response_action: Mapped[str] = mapped_column(String(160), nullable=False)
    tactic: Mapped[str | None] = mapped_column(String(128))
    technique: Mapped[str | None] = mapped_column(String(128))
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class ThreatIntelIndicator(Base):
    """Threat intelligence indicator such as a malicious IP or domain."""
    __tablename__ = "soc_threat_intel_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class CaseRecord(Base):
    """Structured investigation case linked to an incident or analyst workflow."""
    __tablename__ = "soc_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    incident_reference: Mapped[str | None] = mapped_column(ForeignKey("soc_incidents.id"))
    assigned_analyst: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    investigation_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_files: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Open")
    resolution_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class AutomationPlaybook(Base):
    """SOAR-style playbook describing automated or approval-based response steps."""
    __tablename__ = "soc_playbooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    trigger_event: Mapped[str] = mapped_column(String(128), nullable=False)
    steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class PostureSnapshot(Base):
    """Point-in-time security posture measurement for an environment."""
    __tablename__ = "soc_posture_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    environment_name: Mapped[str] = mapped_column(String(128), nullable=False)
    patch_status: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerable_software: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inactive_security_controls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unsecured_services: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    posture_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class CorrelationRecord(Base):
    """SIEM-style correlation result linking multiple related security events."""
    __tablename__ = "soc_correlations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    correlation_name: Mapped[str] = mapped_column(String(160), nullable=False)
    event_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("soc_incidents.id"))
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class AIAnomalyFinding(Base):
    """Stored AI anomaly result linked back to the originating security event."""
    __tablename__ = "soc_ai_anomaly_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    device_id: Mapped[str | None] = mapped_column(String(120))
    event_id: Mapped[str | None] = mapped_column(ForeignKey("soc_security_events.id"))
    anomaly_type: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recommended_action: Mapped[str] = mapped_column(String(160), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class RedTeamSimulation(Base):
    """
    Recorded red-team or validation scenario used to test detection coverage.

    The simulation record is intentionally richer than a simple "scenario was
    run" flag. Analysts need to understand what was simulated, which identity
    or device was targeted, whether the lab stayed inside a safe environment,
    and which timeline of events drove downstream detections.
    """
    __tablename__ = "soc_red_team_simulations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    scenario_name: Mapped[str] = mapped_column(String(160), nullable=False)
    scenario_type: Mapped[str] = mapped_column(String(64), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    intensity_level: Mapped[str] = mapped_column(String(16), nullable=False, default="Medium")
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    target_user: Mapped[str | None] = mapped_column(String(255))
    target_device: Mapped[str | None] = mapped_column(String(120))
    training_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Planned")
    safety_status: Mapped[str] = mapped_column(String(32), nullable=False, default="Isolated")
    safety_notes: Mapped[str] = mapped_column(Text, nullable=False, default="Simulation restricted to lab-only telemetry.")
    expected_detection: Mapped[str] = mapped_column(Text, nullable=False)
    scenario_config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    timeline: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    detection_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class ThreatHuntQuery(Base):
    """
    Saved threat-hunting query used by analysts to repeat common investigations.

    Saved hunts matter operationally because mature SOC teams tend to reuse the
    same investigative hypotheses during triage, purple teaming, and periodic
    threat-hunt exercises.
    """
    __tablename__ = "soc_threat_hunt_queries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    filters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class ThreatHuntReport(Base):
    """
    Report generated from a hunt session for handoff, audit, or documentation.

    Reports preserve the analyst narrative: what was searched, what evidence
    was found, how it mapped to attacker behavior, and what mitigation is
    recommended next.
    """
    __tablename__ = "soc_threat_hunt_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    query_id: Mapped[str | None] = mapped_column(ForeignKey("soc_threat_hunt_queries.id"))
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    events_analyzed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    identified_threats: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recommended_mitigations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    export_format: Mapped[str] = mapped_column(String(32), nullable=False, default="json")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Device(Base):
    """Monitored endpoint or system with encrypted network context."""
    __tablename__ = "soc_devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    device_id: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    device_type: Mapped[str] = mapped_column(String(64), nullable=False, default="Unknown")
    ip_address: Mapped[str] = mapped_column(EncryptedString(), nullable=False)
    location: Mapped[str | None] = mapped_column(EncryptedString())
    login_history: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Session(Base):
    """Tracked authenticated API session used for Zero Trust validation."""
    __tablename__ = "soc_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("soc_users.id"), nullable=False)
    jwt_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(120))
    ip_address: Mapped[str | None] = mapped_column(EncryptedString())
    user_agent: Mapped[str | None] = mapped_column(EncryptedString())
    status: Mapped[str] = mapped_column(String(32), default="verified", nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    user: Mapped[User] = relationship(back_populates="sessions")


class LogEntry(Base):
    """Audit log entry describing an API action or security-relevant event."""
    __tablename__ = "soc_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("soc_tenants.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("soc_users.id"))
    ip_address: Mapped[str | None] = mapped_column(EncryptedString())
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)
