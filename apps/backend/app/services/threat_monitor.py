"""
SOC-CyBe Security Platform
Module: Threat Monitoring Service

Purpose:
This module handles suspicious login detection, alert creation, event creation,
behavioral alerting, and threat analysis summaries.

Security Considerations:
- Login anomalies are important even when authentication fails, because failed
  attempts can indicate brute-force or reconnaissance activity.
- Alerts and events are stored separately so analysts can view concise alerts
  while investigators retain access to the underlying evidence.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import Alert, Device, RiskScore, SecurityEvent, User
from app.schemas.threats import ThreatAnalysisResponse, ThreatEventItem
from app.services.risk_engine import calculate_risk_score


def severity_from_score(score: int) -> str:
    """Translate a numeric risk-oriented score into an analyst-friendly severity."""
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def create_alert(
    db: Session,
    *,
    tenant_id: str | None,
    title: str,
    severity: str,
    source: str,
    event_id: str | None = None,
    status: str = "Open",
) -> Alert:
    """Create an alert record that can be shown in the SOC dashboard."""
    alert = Alert(
        tenant_id=tenant_id,
        event_id=event_id,
        severity=severity,
        title=title,
        source=source,
        status=status,
    )
    db.add(alert)
    db.flush()
    return alert


def create_security_event(
    db: Session,
    *,
    tenant_id: str | None,
    user_id: str | None,
    event_type: str,
    severity: str,
    source: str,
    event_payload: dict,
    alert_title: str | None = None,
) -> SecurityEvent:
    """
    Create a security event and optionally raise a corresponding alert.

    This helper keeps the event/alert coupling consistent across detections.
    """
    event = SecurityEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        source=source,
        event_payload=event_payload,
    )
    db.add(event)
    db.flush()
    if alert_title:
        create_alert(db, tenant_id=tenant_id, title=alert_title, severity=severity, source=source, event_id=event.id)
    return event


def evaluate_login_attempt(
    db: Session,
    *,
    user: User | None,
    email: str,
    ip_address: str,
    device_id: str,
    succeeded: bool,
) -> None:
    """
    Evaluate whether a login attempt should be treated as suspicious.

    The logic looks for repeated failures, new devices, and IP shifts because
    those patterns commonly appear during account compromise attempts.
    """
    if user is None:
        create_security_event(
            db,
            tenant_id=None,
            user_id=None,
            event_type="failed_login_unknown_user",
            severity="Medium",
            source="identity-monitor",
            event_payload={"email": email, "ip_address": ip_address, "device_id": device_id},
            alert_title="Unknown-user login attempt detected",
        )
        db.commit()
        return

    risk = user.risk_score
    if not risk:
        return

    suspicious_reasons: list[str] = []
    known_device = db.scalar(select(Device).where(Device.device_id == device_id, Device.user_id == user.id))

    if not succeeded:
        suspicious_reasons.append("failed_login")
        if risk.failed_logins >= 3:
            suspicious_reasons.append("repeated_failures")

    if succeeded and not known_device:
        suspicious_reasons.append("new_device")

    if succeeded:
        latest_device = db.scalar(
            select(Device).where(Device.user_id == user.id).order_by(Device.created_at.desc()).limit(1)
        )
        if latest_device and latest_device.ip_address != ip_address:
            suspicious_reasons.append("new_ip")

    if suspicious_reasons:
        recomputed = calculate_risk_score(
            failed_logins=risk.failed_logins,
            ip_reputation=risk.ip_reputation,
            device_trust=risk.device_trust,
            privilege_changes=risk.privilege_changes,
        )
        severity = severity_from_score(recomputed + (10 if succeeded else 15))
        create_security_event(
            db,
            tenant_id=user.tenant_id,
            user_id=user.id,
            event_type="suspicious_login_detected",
            severity=severity,
            source="identity-monitor",
            event_payload={
                "email": email,
                "ip_address": ip_address,
                "device_id": device_id,
                "reasons": suspicious_reasons,
                "succeeded": succeeded,
            },
            alert_title="Suspicious login activity detected",
        )
    db.commit()


def record_behavioral_alert(
    db: Session,
    *,
    tenant_id: str | None,
    user_id: str,
    source: str,
    title: str,
    anomaly_flags: list[str],
    request_path: str,
    severity: str,
) -> None:
    """Promote anomalous request behavior into a stored event and alert."""
    create_security_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        event_type="abnormal_behavior_detected",
        severity=severity,
        source=source,
        event_payload={"request_path": request_path, "anomaly_flags": anomaly_flags},
        alert_title=title,
    )


def build_threat_analysis(db: Session, tenant_id: str | None, hours: int = 24) -> ThreatAnalysisResponse:
    """Summarize recent threat activity for dashboards and analyst review."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = db.scalars(
        select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.created_at >= since).order_by(SecurityEvent.created_at.desc()).limit(25)
    ).all()
    alerts_count = db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == tenant_id, Alert.created_at >= since)) or 0
    suspicious_logins = sum(1 for event in events if event.event_type == "suspicious_login_detected")
    abnormal_behaviors = sum(1 for event in events if event.event_type == "abnormal_behavior_detected")
    escalations = sum(
        1
        for event in events
        if event.event_type in {"authorization_failure", "zero_trust_denial", "step_up_required"}
    )
    source_rows = db.execute(
        select(SecurityEvent.source, func.count(SecurityEvent.id))
        .where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.created_at >= since)
        .group_by(SecurityEvent.source)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(5)
    ).all()
    return ThreatAnalysisResponse(
        suspicious_logins=suspicious_logins,
        abnormal_behaviors=abnormal_behaviors,
        escalations=escalations,
        alert_volume=alerts_count,
        top_sources=[{"source": source, "count": count} for source, count in source_rows],
        recent_events=[
            ThreatEventItem(
                id=event.id,
                event_type=event.event_type,
                severity=event.severity,
                source=event.source,
                created_at=event.created_at.replace(tzinfo=timezone.utc),
                summary=str(event.event_payload)[:180],
            )
            for event in events
        ],
    )
