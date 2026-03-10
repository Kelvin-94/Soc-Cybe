"""
SOC-CyBe Security Platform
Module: Threat Hunting Engine

Purpose:
This module implements proactive threat-hunting workflows over stored SOC
telemetry. It lets analysts search historical events, reconstruct timelines,
highlight suspicious behavior patterns, correlate hits with threat
intelligence, and turn hunt results into formal response artifacts.

Architecture Notes:
- The engine reads from security-event storage instead of bypassing the main
  pipeline. That means hunts operate on the same normalized evidence used by
  alerts, AI findings, correlation, and incident response.
- AI findings and MITRE metadata are layered into hunt results so analysts can
  pivot from raw events to attacker-technique context quickly.

Security Notes:
- Searches remain tenant-scoped at the service layer to avoid data leakage in
  shared deployments.
- The engine does not allow arbitrary query execution. Analysts express intent
  through typed filters that can be audited and validated.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, time, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    AIAnomalyFinding,
    Alert,
    DetectionRule,
    SecurityEvent,
    ThreatHuntQuery,
    ThreatHuntReport,
    ThreatIntelIndicator,
)
from app.schemas.hunting import (
    SavedThreatHuntCreate,
    ThreatHuntPromoteRequest,
    ThreatHuntPromoteResponse,
    ThreatHuntReportCreate,
    ThreatHuntSearchRequest,
    ThreatHuntSearchResponse,
    ThreatHuntResultItem,
    ThreatHuntTimelineItem,
)
from app.schemas.incidents import IncidentCreate
from app.services.incident_response import create_incident_ticket
from app.services.soc_operations import create_case


MITRE_FALLBACKS: dict[str, tuple[str, str, str]] = {
    "failed_login": ("Credential Access", "Brute Force", "T1110"),
    "login": ("Initial Access", "Valid Accounts", "T1078"),
    "user_role_change": ("Privilege Escalation", "Valid Accounts", "T1078"),
    "privilege_change_request": ("Privilege Escalation", "Valid Accounts", "T1078"),
    "database_access": ("Collection", "Data from Information Repositories", "T1213"),
    "file_download": ("Collection", "Archive Collected Data", "T1560"),
    "external_connection": ("Exfiltration", "Exfiltration Over Web Service", "T1567"),
    "process_creation": ("Execution", "Command and Scripting Interpreter", "T1059"),
    "file_modification": ("Persistence", "Create or Modify System Process", "T1543"),
}


def _ensure_tz(value: datetime) -> datetime:
    """Normalize timestamps so timeline sorting stays consistent."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _payload_str(event: SecurityEvent) -> str:
    """Return a compact string form of the event payload for text matching."""
    return str(event.event_payload or {})


def _extract_username(event: SecurityEvent) -> str | None:
    payload = event.event_payload or {}
    return payload.get("username") or payload.get("email")


def _extract_ip(event: SecurityEvent) -> str | None:
    payload = event.event_payload or {}
    return payload.get("source_ip") or payload.get("ip_address") or payload.get("destination_ip")


def _extract_device(event: SecurityEvent) -> str | None:
    payload = event.event_payload or {}
    return payload.get("device_id")


def _event_matches_search(event: SecurityEvent, request: ThreatHuntSearchRequest, ai_scores: dict[str, int]) -> bool:
    """Apply validated hunt filters to a single normalized event."""
    payload = event.event_payload or {}

    if request.username and request.username.lower() not in str(_extract_username(event) or "").lower():
        return False
    if request.ip_address and request.ip_address != str(_extract_ip(event) or ""):
        return False
    if request.device_id and request.device_id != str(_extract_device(event) or ""):
        return False
    if request.event_type and request.event_type.lower() not in event.event_type.lower():
        return False
    if request.start_time and _ensure_tz(event.created_at) < _ensure_tz(request.start_time):
        return False
    if request.end_time and _ensure_tz(event.created_at) > _ensure_tz(request.end_time):
        return False
    if request.min_risk_score is not None and ai_scores.get(event.id, 0) < request.min_risk_score:
        return False
    if request.query_text and request.query_text.lower() not in _payload_str(event).lower():
        return False
    return True


def _mitre_mapping(db: Session, tenant_id: str | None, event: SecurityEvent) -> tuple[str | None, str | None, str | None]:
    """
    Resolve MITRE ATT&CK metadata for an event.

    Detection rules are preferred because they reflect tenant-specific hunting
    and detection policy. A fallback mapping is used when the event type has no
    explicit rule coverage yet.
    """
    rules = db.scalars(
        select(DetectionRule).where(
            DetectionRule.tenant_id == tenant_id,
            DetectionRule.is_active.is_(True),
        )
    ).all()
    for rule in rules:
        conditions = rule.event_conditions or {}
        if conditions.get("event_type") == event.event_type:
            return rule.tactic, rule.technique, rule.mitre_technique_id
    return MITRE_FALLBACKS.get(event.event_type, (None, None, None))


def _intel_matches(indicators: list[ThreatIntelIndicator], event: SecurityEvent) -> list[str]:
    """Return matching indicator values found in an event payload."""
    values = {str(value) for value in (event.event_payload or {}).values() if value is not None}
    return [indicator.indicator_value for indicator in indicators if indicator.indicator_value in values]


def _behavioral_patterns(events: list[SecurityEvent]) -> list[str]:
    """
    Highlight behavior patterns that deserve analyst attention.

    These heuristics are intentionally transparent so analysts can understand
    why the hunt engine suggested a pattern instead of treating it as opaque AI.
    """
    patterns: list[str] = []
    user_hours: dict[str, list[int]] = defaultdict(list)
    user_devices: dict[str, set[str]] = defaultdict(set)
    api_counts: Counter[str] = Counter()
    download_counts: Counter[str] = Counter()

    for event in events:
        username = _extract_username(event)
        device_id = _extract_device(event)
        payload = event.event_payload or {}
        created_at = _ensure_tz(event.created_at)

        if username:
            user_hours[username].append(created_at.hour)
        if username and device_id:
            user_devices[username].add(device_id)
        if "api" in event.event_type.lower():
            api_counts[username or "unknown"] += int(payload.get("count", 1))
        if event.event_type in {"file_download", "database_access", "external_connection"}:
            download_counts[username or "unknown"] += int(payload.get("count", 1))

    for username, hours in user_hours.items():
        if any(hour < 5 or hour > 22 for hour in hours):
            patterns.append(f"{username} shows activity outside normal hours.")
    for username, devices in user_devices.items():
        if len(devices) >= 2:
            patterns.append(f"{username} used multiple devices during the hunt window.")
    for username, count in api_counts.items():
        if count >= 25:
            patterns.append(f"{username} generated unusual API request volume.")
    for username, count in download_counts.items():
        if count >= 40:
            patterns.append(f"{username} shows high-volume data collection or transfer behavior.")
    return patterns


def _ai_suggestions(request: ThreatHuntSearchRequest, results: list[ThreatHuntResultItem]) -> list[str]:
    """Generate analyst-friendly next-query suggestions from hunt results."""
    suggestions: list[str] = []
    if not results:
        return [
            "Broaden the time range and search for login or privilege events with a lower risk threshold.",
            "Pivot on a monitored device ID or IP address instead of a username-only hypothesis.",
        ]

    if request.event_type != "login":
        suggestions.append("Pivot into login events for the same user to look for initial access patterns.")
    if any(result.risk_score >= 65 for result in results):
        suggestions.append("Filter on risk_score >= 65 and review the associated AI anomaly findings.")
    if any(result.intel_matches for result in results):
        suggestions.append("Expand the query around IPs or domains that matched threat intelligence indicators.")
    if any(result.mitre_tactic == "Privilege Escalation" for result in results):
        suggestions.append("Search for role changes, token abuse, or administrative API usage for the same user.")
    return suggestions[:4]


def run_threat_hunt(db: Session, tenant_id: str | None, request: ThreatHuntSearchRequest) -> ThreatHuntSearchResponse:
    """Run a tenant-scoped proactive hunt across stored security events."""
    events = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(max(request.limit * 4, 100))
    ).all()
    findings = db.scalars(
        select(AIAnomalyFinding).where(AIAnomalyFinding.tenant_id == tenant_id)
    ).all()
    ai_scores = {finding.event_id: finding.risk_score for finding in findings if finding.event_id}
    indicators = db.scalars(
        select(ThreatIntelIndicator).where(ThreatIntelIndicator.tenant_id == tenant_id, ThreatIntelIndicator.status == "Active")
    ).all()

    filtered = [event for event in events if _event_matches_search(event, request, ai_scores)][: request.limit]
    timeline = sorted(filtered, key=lambda event: _ensure_tz(event.created_at))

    results: list[ThreatHuntResultItem] = []
    for event in filtered:
        tactic, technique, technique_id = _mitre_mapping(db, tenant_id, event)
        results.append(
            ThreatHuntResultItem(
                event_id=event.id,
                event_type=event.event_type,
                severity=event.severity,
                source=event.source,
                username=_extract_username(event),
                ip_address=_extract_ip(event),
                device_id=_extract_device(event),
                created_at=_ensure_tz(event.created_at),
                risk_score=ai_scores.get(event.id, 0),
                summary=_payload_str(event)[:220],
                mitre_tactic=tactic,
                mitre_technique=technique,
                mitre_technique_id=technique_id,
                intel_matches=_intel_matches(indicators, event),
            )
        )

    query_summary_parts = [
        f"event_type={request.event_type}" if request.event_type else None,
        f"username={request.username}" if request.username else None,
        f"ip_address={request.ip_address}" if request.ip_address else None,
        f"device_id={request.device_id}" if request.device_id else None,
        f"risk_score>={request.min_risk_score}" if request.min_risk_score is not None else None,
    ]
    summary = "Threat hunt over security-event storage"
    active_filters = [part for part in query_summary_parts if part]
    if active_filters:
        summary = f"{summary}: " + ", ".join(active_filters)

    return ThreatHuntSearchResponse(
        query_summary=summary,
        total_results=len(results),
        results=results,
        timeline=[
            ThreatHuntTimelineItem(
                timestamp=_ensure_tz(event.created_at),
                event_id=event.id,
                event_type=event.event_type,
                description=_payload_str(event)[:180],
                source=event.source,
            )
            for event in timeline
        ],
        behavioral_patterns=_behavioral_patterns(filtered),
        ai_suggestions=_ai_suggestions(request, results),
    )


def save_threat_hunt_query(
    db: Session,
    *,
    tenant_id: str | None,
    user_id: str,
    payload: SavedThreatHuntCreate,
) -> ThreatHuntQuery:
    """Persist a reusable hunting query for future analyst workflows."""
    record = ThreatHuntQuery(
        tenant_id=tenant_id,
        created_by_user_id=user_id,
        name=payload.name,
        description=payload.description,
        filters=payload.filters,
        notes=payload.notes,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def build_threat_hunt_report(
    db: Session,
    *,
    tenant_id: str | None,
    user_id: str,
    payload: ThreatHuntReportCreate,
) -> ThreatHuntReport:
    """Create an exportable hunt report for handoff or audit evidence."""
    report = ThreatHuntReport(
        tenant_id=tenant_id,
        created_by_user_id=user_id,
        query_id=payload.query_id,
        title=payload.title,
        summary=payload.summary,
        events_analyzed=payload.events_analyzed,
        identified_threats=payload.identified_threats,
        recommended_mitigations=payload.recommended_mitigations,
        export_format=payload.export_format,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def promote_hunt_to_incident(
    db: Session,
    *,
    tenant_id: str | None,
    user_id: str,
    payload: ThreatHuntPromoteRequest,
) -> ThreatHuntPromoteResponse:
    """
    Turn a hunt finding into an alert, incident, and investigation case.

    This closes the gap between proactive hunting and formal incident response,
    which is the main reason hunting features need to live inside the SOC
    platform instead of an external notebook or ad-hoc search tool.
    """
    alert = Alert(
        tenant_id=tenant_id,
        severity=payload.severity,
        title=payload.title,
        status="Open",
        source="threat-hunting-engine",
    )
    db.add(alert)
    db.flush()

    incident = create_incident_ticket(
        db,
        tenant_id=tenant_id,
        payload=IncidentCreate(
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            affected_asset=payload.affected_asset,
        ),
        owner_user_id=user_id,
    )
    case = create_case(
        db,
        tenant_id=tenant_id,
        incident_reference=incident.id,
        assigned_analyst=user_id,
        investigation_notes=f"Threat hunt promoted to incident. Evidence events: {', '.join(payload.evidence_event_ids) or 'none supplied'}",
        evidence_files=payload.evidence_event_ids,
    )
    return ThreatHuntPromoteResponse(
        alert_id=alert.id,
        incident_id=incident.id,
        case_id=case.id,
        status="promoted-to-response-workflow",
    )
