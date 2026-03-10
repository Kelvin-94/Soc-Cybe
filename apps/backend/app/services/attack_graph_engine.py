"""
SOC-CyBe Security Platform
Module: Attack Graph Engine

Purpose:
This module projects recent security events into a visual attack graph. It
connects users, devices, systems, files, sessions, and IP addresses so
analysts can understand attack progression and lateral movement at a glance.

Architecture Notes:
- The graph is built from normalized security events already stored by the SOC.
- AI findings, alerts, and threat-intelligence hits are folded into node risk
  so the visual layer reflects the same priorities the rest of the platform
  uses.
- The service is deliberately stateless for the MVP. A production deployment
  could replace or augment this with a graph database such as Neo4j without
  changing the API contracts.

Security Notes:
- All graph data is derived from tenant-scoped evidence only.
- The graph helps reduce analyst blind spots, but it does not replace raw
  evidence review. Each node and edge still links back to underlying events.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import AIAnomalyFinding, Alert, Incident, SecurityEvent, ThreatIntelIndicator
from app.schemas.attack_graph import AttackGraphEdge, AttackGraphNode, AttackGraphResponse, AttackGraphTimelineItem


def _ensure_tz(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _risk_level(score: int) -> tuple[str, str]:
    if score >= 85:
        return "Critical", "#ff5678"
    if score >= 65:
        return "High", "#ff9c54"
    if score >= 40:
        return "Medium", "#ffd166"
    return "Low", "#52f2d7"


def _add_node(nodes: dict[str, dict], *, node_id: str, node_type: str, label: str, risk_score: int, intel_match: bool, details: dict) -> None:
    current = nodes.get(node_id)
    if current is None:
        level, color = _risk_level(risk_score)
        nodes[node_id] = {
            "id": node_id,
            "node_type": node_type,
            "label": label,
            "risk_score": risk_score,
            "risk_level": level,
            "color": color,
            "intel_match": intel_match,
            "alert_count": 0,
            "details": details,
        }
        return

    current["risk_score"] = max(current["risk_score"], risk_score)
    current["intel_match"] = current["intel_match"] or intel_match
    current["details"] = {**current["details"], **details}
    level, color = _risk_level(current["risk_score"])
    current["risk_level"] = level
    current["color"] = color


def _node_key(prefix: str, value: str | None) -> str | None:
    if not value:
        return None
    return f"{prefix}:{value}"


def build_attack_graph(db: Session, tenant_id: str | None, *, incident_id: str | None = None, limit: int = 120) -> AttackGraphResponse:
    """
    Build a visual attack graph from recent security events.

    Incident focus is optional. When provided, the graph prefers events related
    to the incident's affected asset so the analyst can quickly scope the case.
    """
    events = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
    ).all()
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)) if incident_id else None
    if incident:
        asset = incident.affected_asset.lower()
        filtered = [
            event
            for event in events
            if asset in str(event.source).lower() or asset in str(event.event_payload or {}).lower()
        ]
        events = filtered or events[:40]

    ai_findings = db.scalars(select(AIAnomalyFinding).where(AIAnomalyFinding.tenant_id == tenant_id)).all()
    ai_scores = {finding.event_id: finding.risk_score for finding in ai_findings if finding.event_id}
    alerts = db.scalars(select(Alert).where(Alert.tenant_id == tenant_id, Alert.status != "Resolved")).all()
    indicators = db.scalars(select(ThreatIntelIndicator).where(ThreatIntelIndicator.tenant_id == tenant_id, ThreatIntelIndicator.status == "Active")).all()
    alert_by_event = Counter(alert.event_id for alert in alerts if alert.event_id)

    nodes: dict[str, dict] = {}
    edges: list[AttackGraphEdge] = []
    timeline: list[AttackGraphTimelineItem] = []
    user_devices: defaultdict[str, set[str]] = defaultdict(set)
    device_targets: defaultdict[str, set[str]] = defaultdict(set)

    for event in sorted(events, key=lambda row: _ensure_tz(row.created_at)):
        payload = event.event_payload or {}
        username = payload.get("username") or payload.get("email")
        device_id = payload.get("device_id")
        source_ip = payload.get("source_ip") or payload.get("ip_address")
        destination_ip = payload.get("destination_ip")
        file_path = payload.get("file_path")
        session_id = payload.get("session_id")
        application = payload.get("application") or event.source

        risk_score = ai_scores.get(event.id, 25 if event.severity == "Low" else 45 if event.severity == "Medium" else 70 if event.severity == "High" else 90)
        intel_values = {str(value) for value in payload.values() if value is not None}
        intel_match = any(indicator.indicator_value in intel_values for indicator in indicators)
        if intel_match:
            risk_score = max(risk_score, 85)

        user_key = _node_key("user", str(username)) if username else None
        device_key = _node_key("device", str(device_id)) if device_id else None
        source_ip_key = _node_key("ip", str(source_ip)) if source_ip else None
        destination_ip_key = _node_key("ip", str(destination_ip)) if destination_ip else None
        file_key = _node_key("file", str(file_path)) if file_path else None
        session_key = _node_key("session", str(session_id)) if session_id else None
        application_key = _node_key("application", str(application)) if application else None

        if user_key:
            _add_node(nodes, node_id=user_key, node_type="user", label=str(username), risk_score=risk_score, intel_match=False, details={"username": username})
        if device_key:
            _add_node(nodes, node_id=device_key, node_type="device", label=str(device_id), risk_score=risk_score, intel_match=False, details={"device_id": device_id})
        if source_ip_key:
            _add_node(nodes, node_id=source_ip_key, node_type="ip_address", label=str(source_ip), risk_score=risk_score, intel_match=intel_match, details={"ip_address": source_ip})
        if destination_ip_key:
            _add_node(nodes, node_id=destination_ip_key, node_type="ip_address", label=str(destination_ip), risk_score=risk_score, intel_match=intel_match, details={"ip_address": destination_ip})
        if file_key:
            _add_node(nodes, node_id=file_key, node_type="file", label=str(file_path), risk_score=risk_score, intel_match=False, details={"file_path": file_path})
        if session_key:
            _add_node(nodes, node_id=session_key, node_type="session", label=str(session_id), risk_score=risk_score, intel_match=False, details={"session_id": session_id})
        if application_key:
            _add_node(nodes, node_id=application_key, node_type="application", label=str(application), risk_score=risk_score, intel_match=False, details={"application": application})

        if user_key and device_key:
            user_devices[user_key].add(device_key)
            edges.append(
                AttackGraphEdge(
                    id=f"edge:{event.id}:user-device",
                    source=user_key,
                    target=device_key,
                    action="login_attempt" if "login" in event.event_type else event.event_type,
                    timestamp=_ensure_tz(event.created_at),
                    source_system="identity",
                    destination_system=str(device_id),
                    severity=event.severity,
                    details={"event_id": event.id, "source": event.source},
                )
            )
        if device_key and destination_ip_key:
            device_targets[device_key].add(destination_ip_key)
            edges.append(
                AttackGraphEdge(
                    id=f"edge:{event.id}:device-destination",
                    source=device_key,
                    target=destination_ip_key,
                    action="network_connection" if "connection" in event.event_type else event.event_type,
                    timestamp=_ensure_tz(event.created_at),
                    source_system=str(device_id),
                    destination_system=str(destination_ip),
                    severity=event.severity,
                    details={"event_id": event.id, "source": event.source},
                )
            )
        if user_key and application_key:
            edges.append(
                AttackGraphEdge(
                    id=f"edge:{event.id}:user-application",
                    source=user_key,
                    target=application_key,
                    action=event.event_type,
                    timestamp=_ensure_tz(event.created_at),
                    source_system=str(username),
                    destination_system=str(application),
                    severity=event.severity,
                    details={"event_id": event.id, "source": event.source},
                )
            )
        if application_key and file_key:
            edges.append(
                AttackGraphEdge(
                    id=f"edge:{event.id}:application-file",
                    source=application_key,
                    target=file_key,
                    action="file_access",
                    timestamp=_ensure_tz(event.created_at),
                    source_system=str(application),
                    destination_system=str(file_path),
                    severity=event.severity,
                    details={"event_id": event.id, "source": event.source},
                )
            )
        if user_key and session_key:
            edges.append(
                AttackGraphEdge(
                    id=f"edge:{event.id}:user-session",
                    source=user_key,
                    target=session_key,
                    action="session_activity",
                    timestamp=_ensure_tz(event.created_at),
                    source_system=str(username),
                    destination_system=str(session_id),
                    severity=event.severity,
                    details={"event_id": event.id, "source": event.source},
                )
            )

        timeline.append(
            AttackGraphTimelineItem(
                timestamp=_ensure_tz(event.created_at),
                event_id=event.id,
                action=event.event_type,
                actor=str(username) if username else None,
                target=str(device_id or destination_ip or file_path or application) if (device_id or destination_ip or file_path or application) else None,
                severity=event.severity,
                description=str(payload)[:200],
            )
        )

        for node_id in filter(None, [user_key, device_key, source_ip_key, destination_ip_key, file_key, session_key, application_key]):
            if node_id in nodes:
                nodes[node_id]["alert_count"] += alert_by_event.get(event.id, 0)

    lateral_paths: list[list[str]] = []
    for user_key, devices in user_devices.items():
        if len(devices) >= 2:
            lateral_paths.append([user_key, *sorted(devices)])
    for device_key, targets in device_targets.items():
        if len(targets) >= 2:
            lateral_paths.append([device_key, *sorted(targets)])

    suggestions: list[str] = []
    if lateral_paths:
        suggestions.append("Possible lateral movement detected across multiple devices or internal destinations.")
    if sum(1 for node in nodes.values() if node["intel_match"]) > 0:
        suggestions.append("Threat-intelligence matches present in the attack path. Prioritize containment.")
    if any(node["risk_score"] >= 85 for node in nodes.values()):
        suggestions.append("Critical-risk nodes suggest a concentrated attack chain worth immediate scoping.")
    if not suggestions:
        suggestions.append("No dominant attack chain detected yet. Continue monitoring for path expansion.")

    open_incidents = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id, Incident.status != "Closed")
    ) or 0

    return AttackGraphResponse(
        incident_id=incident_id,
        active_attack_paths=max(1 if edges else 0, len(lateral_paths)),
        compromised_devices=sum(1 for node in nodes.values() if node["node_type"] == "device" and node["risk_score"] >= 65),
        high_risk_users=sum(1 for node in nodes.values() if node["node_type"] == "user" and node["risk_score"] >= 65),
        ongoing_incidents=open_incidents,
        ai_attack_path_suggestions=suggestions,
        lateral_movement_paths=lateral_paths,
        nodes=[AttackGraphNode(**node) for node in nodes.values()],
        edges=edges[-120:],
        timeline=timeline[-120:],
    )
