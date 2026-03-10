"""
SOC-CyBe Security Platform
Module: Zero Trust Decision Service

Purpose:
This service evaluates request context, detects anomalies, updates risk
posture, and records security events that explain access decisions.

Security Considerations:
- The platform never trusts a token alone; request context still matters.
- Anomalies are preserved as structured evidence for correlation, alerting,
  and later investigation.
- This module is central to SOC-CyBe's "verify every request" posture.
"""

from datetime import datetime, timezone
from urllib.parse import unquote

from sqlalchemy.orm import Session

from app.models.entities import RiskScore, SecurityEvent, Session as UserSession
from app.services.risk_engine import calculate_risk_score, evaluate_request_risk


SENSITIVE_ENDPOINT_MARKERS = ("/roles", "/incidents", "/risk", "/sessions", "/audit-logs")
ANOMALY_PATTERNS = ("../", "<script", " union ", " select ", "drop table", ";--", "$((", "||", "%3cscript")


def detect_request_anomalies(path: str, query_string: str, user_agent: str | None) -> list[str]:
    """
    Identify suspicious traits in a request target before business logic runs.

    The patterns here are intentionally conservative and are meant to flag
    likely abuse rather than perform exhaustive attack detection.
    """
    raw = f"{path}?{query_string}".lower()
    decoded = unquote(raw)
    flags: list[str] = []
    if any(pattern in decoded for pattern in ANOMALY_PATTERNS):
        flags.append("payload-pattern")
    if not user_agent:
        flags.append("missing-user-agent")
    if len(decoded) > 600:
        flags.append("oversized-request-target")
    return flags


def assess_zero_trust_access(
    *,
    risk_score: RiskScore | None,
    session: UserSession,
    request_path: str,
    request_query: str,
    client_ip: str,
    user_agent: str | None,
    permission: str | None = None,
) -> tuple[int, str, dict[str, int | str | bool], list[str]]:
    """
    Combine stored risk, live request context, and anomaly flags into a decision.

    The return tuple includes a score, a policy decision, a structured factor
    map for logging, and the list of anomaly flags seen on the request.
    """
    current_time = datetime.now(timezone.utc)
    session_age_minutes = max(0, int((current_time - session.created_at.replace(tzinfo=timezone.utc)).total_seconds() // 60))
    new_ip = bool(session.ip_address and client_ip != session.ip_address)
    sensitive_action = any(marker in request_path for marker in SENSITIVE_ENDPOINT_MARKERS) or bool(
        permission and permission.endswith(":write")
    )
    privilege_escalation_signal = bool(permission and permission in {"users:manage", "incidents:write"} and risk_score and risk_score.score >= 45)
    anomaly_flags = detect_request_anomalies(request_path, request_query, user_agent)
    request_risk, decision = evaluate_request_risk(
        base_risk_score=risk_score.score if risk_score else 20,
        device_trust=risk_score.device_trust if risk_score else 100,
        new_ip=new_ip,
        session_age_minutes=session_age_minutes,
        sensitive_action=sensitive_action,
        anomaly_flags=len(anomaly_flags),
        privilege_escalation_signal=privilege_escalation_signal,
    )
    factors = {
        "base_risk_score": risk_score.score if risk_score else 20,
        "device_trust": risk_score.device_trust if risk_score else 100,
        "new_ip": new_ip,
        "session_age_minutes": session_age_minutes,
        "sensitive_action": sensitive_action,
        "anomaly_flags": len(anomaly_flags),
        "privilege_escalation_signal": privilege_escalation_signal,
    }
    return request_risk, decision, factors, anomaly_flags


def update_risk_from_request(risk_score: RiskScore | None, request_risk: int) -> None:
    """Merge request-level risk back into the persisted user risk profile."""
    if not risk_score:
        return
    risk_score.score = calculate_risk_score(
        failed_logins=risk_score.failed_logins,
        ip_reputation=risk_score.ip_reputation,
        device_trust=risk_score.device_trust,
        privilege_changes=risk_score.privilege_changes,
    )
    risk_score.score = max(risk_score.score, request_risk)
    risk_score.updated_at = datetime.utcnow()


def log_security_event(
    db: Session,
    *,
    tenant_id: str | None,
    user_id: str | None,
    event_type: str,
    severity: str,
    source: str,
    event_payload: dict,
) -> None:
    """
    Persist a structured security event for downstream detection and audit use.

    Events created here are later consumed by dashboards, correlation logic,
    incident workflows, and compliance reporting.
    """
    db.add(
        SecurityEvent(
            tenant_id=tenant_id,
            user_id=user_id,
            event_type=event_type,
            severity=severity,
            source=source,
            event_payload=event_payload,
        )
    )
