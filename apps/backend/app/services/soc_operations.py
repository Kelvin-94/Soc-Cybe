"""
SOC-CyBe Security Platform
Module: Extended SOC Operations Service

Purpose:
This module implements the remaining SOC operational workflows that sit around
the core detection pipeline: rule management, threat intelligence, case
handling, playbooks, posture scoring, correlation, simulations, and tenant
seeding.

Security Considerations:
- Rule and playbook changes directly influence how the SOC reacts to threats,
  so the logic is kept explicit and auditable.
- Tenant-aware helpers prevent one organization's operational data from being
  mixed with another's.
- Threat intelligence and simulation features are designed to improve detection
  coverage without bypassing the existing incident and logging model.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Alert,
    AutomationPlaybook,
    CaseRecord,
    CorrelationRecord,
    DetectionRule,
    Incident,
    PostureSnapshot,
    RedTeamSimulation,
    SecurityEvent,
    ThreatIntelIndicator,
    User,
)
from app.schemas.operations import RuleTestResponse


DEFAULT_RULES = [
    {
        "rule_name": "Brute Force Threshold",
        "event_conditions": {"event_type": "failed_login", "threshold": 10, "window_minutes": 2},
        "severity_level": "High",
        "response_action": "trigger_brute_force_alert",
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "mitre_technique_id": "T1110",
    },
    {
        "rule_name": "Unauthorized Role Change",
        "event_conditions": {"event_type": "user_role_change", "actor_role_not": "Admin"},
        "severity_level": "Critical",
        "response_action": "trigger_privilege_escalation_alert",
        "tactic": "Privilege Escalation",
        "technique": "Valid Accounts",
        "mitre_technique_id": "T1078",
    },
]

DEFAULT_PLAYBOOKS = [
    {
        "name": "Malware Containment",
        "trigger_event": "malware_detected",
        "steps": [
            {"action": "isolate_endpoint"},
            {"action": "revoke_user_session"},
            {"action": "notify_soc_analyst"},
            {"action": "open_incident_ticket"},
        ],
        "requires_approval": False,
    },
    {
        "name": "Credential Attack Containment",
        "trigger_event": "credential_attack_detected",
        "steps": [
            {"action": "lock_compromised_user_account"},
            {"action": "revoke_user_session"},
            {"action": "notify_soc_analyst"},
            {"action": "open_incident_ticket"},
        ],
        "requires_approval": True,
    },
    {
        "name": "Identity Anomaly Review",
        "trigger_event": "identity_anomaly_detected",
        "steps": [
            {"action": "step_up_authentication"},
            {"action": "flag_account_for_review"},
            {"action": "notify_soc_analyst"},
        ],
        "requires_approval": True,
    },
    {
        "name": "Privilege Escalation Containment",
        "trigger_event": "privilege_escalation_detected",
        "steps": [
            {"action": "revoke_elevated_request"},
            {"action": "revoke_user_session"},
            {"action": "notify_incident_responder"},
            {"action": "open_incident_ticket"},
        ],
        "requires_approval": False,
    },
    {
        "name": "Data Exfiltration Containment",
        "trigger_event": "data_exfiltration_detected",
        "steps": [
            {"action": "block_malicious_ip"},
            {"action": "isolate_endpoint"},
            {"action": "notify_incident_responder"},
            {"action": "open_incident_ticket"},
        ],
        "requires_approval": False,
    }
]

DEFAULT_THREAT_INTEL = [
    {"indicator_type": "ip", "indicator_value": "185.220.101.1", "provider": "CrowdStrike", "confidence": 92},
    {"indicator_type": "domain", "indicator_value": "malicious-control.example", "provider": "IBM X-Force", "confidence": 88},
]


def seed_soc_modules(db: Session, tenant_id: str | None) -> None:
    """Seed a tenant with baseline rules, playbooks, and threat indicators."""
    existing_rule_names = {row.rule_name for row in db.scalars(select(DetectionRule).where(DetectionRule.tenant_id == tenant_id)).all()}
    for rule in DEFAULT_RULES:
        if rule["rule_name"] in existing_rule_names:
            continue
        db.add(DetectionRule(tenant_id=tenant_id, **rule))

    existing_playbooks = {row.name for row in db.scalars(select(AutomationPlaybook).where(AutomationPlaybook.tenant_id == tenant_id)).all()}
    for playbook in DEFAULT_PLAYBOOKS:
        if playbook["name"] in existing_playbooks:
            continue
        db.add(AutomationPlaybook(tenant_id=tenant_id, **playbook))

    existing_intel = {
        (row.indicator_type, row.indicator_value)
        for row in db.scalars(select(ThreatIntelIndicator).where(ThreatIntelIndicator.tenant_id == tenant_id)).all()
    }
    for indicator in DEFAULT_THREAT_INTEL:
        key = (indicator["indicator_type"], indicator["indicator_value"])
        if key in existing_intel:
            continue
        db.add(ThreatIntelIndicator(tenant_id=tenant_id, **indicator))
    db.commit()


def test_rule(rule: DetectionRule, event_payload: dict) -> RuleTestResponse:
    """
    Run a rule against a sandbox payload without affecting live detections.

    This gives analysts a safe way to test new rules before enabling them.
    """
    conditions = rule.event_conditions or {}
    event_type = conditions.get("event_type")
    matched = event_payload.get("event_type") == event_type if event_type else False
    threshold = conditions.get("threshold")
    if matched and threshold is not None:
        matched = int(event_payload.get("count", 0)) >= int(threshold)
    actor_role_not = conditions.get("actor_role_not")
    if matched and actor_role_not:
        matched = event_payload.get("actor_role") != actor_role_not
    return RuleTestResponse(
        matched=matched,
        severity=rule.severity_level if matched else None,
        response_action=rule.response_action if matched else None,
    )


def evaluate_threat_intel(db: Session, tenant_id: str | None, payload: dict) -> list[ThreatIntelIndicator]:
    """Check an event payload for matches against known malicious indicators."""
    indicators = db.scalars(select(ThreatIntelIndicator).where(ThreatIntelIndicator.tenant_id == tenant_id, ThreatIntelIndicator.status == "Active")).all()
    values = {str(value) for value in payload.values() if value is not None}
    return [indicator for indicator in indicators if indicator.indicator_value in values]


def create_case(db: Session, *, tenant_id: str | None, incident_reference: str | None, assigned_analyst: str | None, investigation_notes: str, evidence_files: list[str]) -> CaseRecord:
    """Open a new analyst case for structured investigation work."""
    record = CaseRecord(
        tenant_id=tenant_id,
        incident_reference=incident_reference,
        assigned_analyst=assigned_analyst,
        investigation_notes=investigation_notes,
        evidence_files=evidence_files,
        status="Open",
        updated_at=datetime.utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def update_case(db: Session, case: CaseRecord, *, notes: str, status: str | None, resolution_summary: str | None) -> CaseRecord:
    """Update investigation notes and lifecycle state for a case."""
    case.investigation_notes = notes
    if status:
        case.status = status
    if resolution_summary is not None:
        case.resolution_summary = resolution_summary
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case)
    return case


def compute_posture_score(*, patch_status: int, vulnerable_software: int, inactive_security_controls: int, unsecured_services: int) -> int:
    """Convert posture inputs into a simple environment security score."""
    score = patch_status
    score -= vulnerable_software * 4
    score -= inactive_security_controls * 8
    score -= unsecured_services * 6
    return max(0, min(score, 100))


def create_posture_snapshot(db: Session, *, tenant_id: str | None, environment_name: str, patch_status: int, vulnerable_software: int, inactive_security_controls: int, unsecured_services: int) -> PostureSnapshot:
    """Store a posture snapshot for later trend analysis and review."""
    snapshot = PostureSnapshot(
        tenant_id=tenant_id,
        environment_name=environment_name,
        patch_status=patch_status,
        vulnerable_software=vulnerable_software,
        inactive_security_controls=inactive_security_controls,
        unsecured_services=unsecured_services,
        posture_score=compute_posture_score(
            patch_status=patch_status,
            vulnerable_software=vulnerable_software,
            inactive_security_controls=inactive_security_controls,
            unsecured_services=unsecured_services,
        ),
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def correlate_recent_events(db: Session, tenant_id: str | None) -> CorrelationRecord | None:
    """
    Correlate recent events into a higher-confidence incident candidate.

    The MVP looks for a specific compromise sequence. Production systems would
    typically support many correlation patterns and richer time windows.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=15)
    events = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.created_at >= since)
        .order_by(SecurityEvent.created_at.desc())
        .limit(10)
    ).all()
    event_types = {event.event_type for event in events}
    pattern = {"suspicious_login_detected", "abnormal_behavior_detected", "zero_trust_denial"}
    if not pattern.issubset(event_types):
        return None
    incident = Incident(
        tenant_id=tenant_id,
        title="Potential account compromise incident",
        description="Correlated suspicious login, anomalous behavior, and denial events.",
        severity="High",
        status="Investigating",
        response_stage="Identification",
        affected_asset="identity-plane",
        owner_user_id=events[0].user_id if events and events[0].user_id else None,
    )
    db.add(incident)
    db.flush()
    correlation = CorrelationRecord(
        tenant_id=tenant_id,
        correlation_name="Potential account compromise incident",
        event_ids=[event.id for event in events[:3]],
        incident_id=incident.id,
        severity="High",
    )
    db.add(correlation)
    db.add(
        Alert(
            tenant_id=tenant_id,
            severity="High",
            title="Correlated account compromise sequence detected",
            status="Open",
            source="correlation-engine",
        )
    )
    db.commit()
    db.refresh(correlation)
    return correlation


def execute_playbook(db: Session, playbook: AutomationPlaybook) -> list[str]:
    """Return the ordered playbook actions that would be executed for a trigger."""
    return [str(step.get("action", "unknown")) for step in playbook.steps]


def create_simulation(db: Session, *, tenant_id: str | None, scenario_name: str, scenario_type: str, expected_detection: str) -> RedTeamSimulation:
    """
    Record a red-team simulation and emit a matching security event.

    Simulation support helps teams validate whether the detection pipeline reacts
    as expected to representative attack scenarios.
    """
    simulation = RedTeamSimulation(
        tenant_id=tenant_id,
        scenario_name=scenario_name,
        scenario_type=scenario_type,
        expected_detection=expected_detection,
        status="Executed",
    )
    db.add(simulation)
    db.add(
        SecurityEvent(
            tenant_id=tenant_id,
            user_id=None,
            event_type=f"red_team_{scenario_type}",
            severity="Medium",
            source="red-team-simulator",
            event_payload={"scenario_name": scenario_name, "expected_detection": expected_detection},
        )
    )
    db.commit()
    db.refresh(simulation)
    return simulation


def delete_user_data(db: Session, *, tenant_id: str | None, user_id: str) -> bool:
    """
    Mark a tenant-scoped user account as deleted and inactive.

    This is the platform's current data deletion control path for compliance
    workflows. It is a conservative first step rather than a full purge engine.
    """
    user = db.scalar(select(User).where(User.id == user_id, User.tenant_id == tenant_id))
    if not user:
        return False
    user.deleted_at = datetime.utcnow()
    user.is_active = False
    db.commit()
    return True
