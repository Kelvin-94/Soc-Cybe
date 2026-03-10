"""
SOC-CyBe Security Platform
Module: API Routes

Purpose:
This module exposes the REST API for the SOC-CyBe platform. It covers
authentication, dashboard views, threat operations, incident response,
compliance controls, ingestion, rule management, automation, posture data,
and AI-assisted anomaly detection.

Security Considerations:
- Protected endpoints rely on the shared dependency layer for Zero Trust checks.
- Route handlers are intentionally thin so security-critical logic lives in
  reusable services rather than duplicated controller code.
- Tenant context is used to keep organizations isolated in shared deployments.
- Streaming endpoints stay tenant-scoped so one organization cannot observe
  another organization's alerts or anomaly findings.
"""

import asyncio
import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.config import settings
from app.core.security import create_access_token, decode_token
from app.db.session import get_db
from app.models.entities import (
    Alert,
    AutomationPlaybook,
    AIAnomalyFinding,
    CaseRecord,
    ConsentRecord,
    CorrelationRecord,
    DetectionRule,
    Incident,
    IncidentActivity,
    LogEntry,
    PostureSnapshot,
    RedTeamSimulation,
    RetentionPolicy,
    Role,
    SecurityEvent,
    Session as UserSession,
    Tenant,
    ThreatIntelIndicator,
    ThreatHuntQuery,
    ThreatHuntReport,
    User,
)
from app.schemas.hunting import (
    SavedThreatHuntCreate,
    SavedThreatHuntResponse,
    ThreatHuntPromoteRequest,
    ThreatHuntPromoteResponse,
    ThreatHuntReportCreate,
    ThreatHuntReportResponse,
    ThreatHuntSearchRequest,
    ThreatHuntSearchResponse,
)
from app.schemas.attack_graph import AttackGraphResponse
from app.schemas.ai import AIFindingResponse, AIScoreResponse, AITrainingRequest, AITrainingResponse
from app.schemas.ingestion import IngestEventRequest, IngestEventResponse
from app.schemas.operations import (
    CaseCreate,
    CaseResponse,
    CaseUpdate,
    CorrelationResponse,
    DeletionRequest,
    DeletionResponse,
    DetectionRuleCreate,
    DetectionRuleResponse,
    PlaybookCreate,
    PlaybookExecutionResponse,
    PlaybookResponse,
    PostureSnapshotCreate,
    PostureSnapshotResponse,
    RuleTestRequest,
    RuleTestResponse,
    SimulationCreate,
    SimulationControlResponse,
    SimulationResponse,
    TenantResponse,
    ThreatIntelCreate,
    ThreatIntelResponse,
)
from app.schemas.compliance import (
    ComplianceReportResponse,
    ConsentRecordResponse,
    ConsentRequest,
    RetentionPolicyResponse,
)
from app.schemas.dashboard import DashboardResponse, DeviceItem, IncidentItem
from app.schemas.incidents import (
    IncidentActivityItem,
    IncidentCreate,
    IncidentResponse,
    IncidentUpdate,
    InvestigationDashboardResponse,
)
from app.schemas.security import AuthenticatedUser, LoginRequest, RiskEvaluation, SessionItem, TokenResponse
from app.schemas.threats import ThreatAnalysisResponse, ThreatEventItem
from app.services.attack_simulation_engine import create_simulation_record, execute_simulation, stop_simulation
from app.services.attack_graph_engine import build_attack_graph
from app.services.auth_service import (
    authenticate_user,
    bootstrap_admin_if_needed,
    collect_permissions,
    record_session,
    seed_roles_and_permissions,
)
from app.services.ai_detection_engine import persist_ai_finding, score_event, train_models
from app.services.compliance import build_compliance_report, record_consent, seed_retention_policies
from app.services.incident_response import (
    append_incident_activity,
    build_investigation_dashboard,
    create_incident_ticket,
    incident_to_response,
)
from app.services.ingestion import enrich_event, normalize_event
from app.services.mock_data import AUDIT_LOGS, DEVICES, INCIDENTS, build_dashboard
from app.services.soc_operations import (
    correlate_recent_events,
    create_case,
    create_posture_snapshot,
    delete_user_data,
    evaluate_threat_intel,
    execute_playbook,
    seed_soc_modules,
    test_rule,
    update_case,
)
from app.services.threat_monitor import build_threat_analysis
from app.services.threat_hunting_engine import (
    build_threat_hunt_report,
    promote_hunt_to_incident,
    run_threat_hunt,
    save_threat_hunt_query,
)


router = APIRouter()


def tenant_scope_id(user: AuthenticatedUser) -> str | None:
    """Return the tenant context attached to the authenticated user."""
    return user.tenant_id


def serialize_alert(row: Alert) -> dict:
    """
    Turn an alert ORM row into the JSON shape used by the dashboard.

    Keeping this translation in one place prevents subtle differences between
    the normal REST feed and the real-time stream.
    """
    return {
        "id": row.id,
        "severity": row.severity,
        "title": row.title,
        "source": row.source,
        "timestamp": row.created_at.isoformat() if row.created_at else None,
        "status": row.status,
    }


def serialize_simulation(row: RedTeamSimulation) -> SimulationResponse:
    """
    Convert a simulation ORM row into the lab response shape used by the UI.

    The simulation lab needs the full context, not only the scenario name, so
    the serializer exposes safety metadata, configuration, and timeline data.
    """
    return SimulationResponse(
        id=row.id,
        scenario_name=row.scenario_name,
        scenario_type=row.scenario_type,
        mode=row.mode,
        intensity_level=row.intensity_level,
        duration_minutes=row.duration_minutes,
        target_user=row.target_user,
        target_device=row.target_device,
        training_mode=row.training_mode,
        scheduled_for=row.scheduled_for,
        started_at=row.started_at,
        completed_at=row.completed_at,
        status=row.status,
        safety_status=row.safety_status,
        safety_notes=row.safety_notes,
        expected_detection=row.expected_detection,
        scenario_config=row.scenario_config or {},
        detection_summary=row.detection_summary or {},
        timeline=row.timeline or [],
    )


@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    user_agent: str | None = Header(default=None),
) -> TokenResponse:
    """
    Endpoint: POST /auth/login

    Purpose:
    Authenticate a user and return a JWT that can be used for protected APIs.

    Security:
    - Login attempts are risk-aware and monitored for suspicious patterns.
    - The resulting token is tied to a tracked session record.
    - Protected endpoints later require both the token and the session.
    """
    user = authenticate_user(
        db,
        payload.email,
        payload.password,
        ip_address=payload.ip_address,
        device_id=payload.device_id,
    )
    if not user or not user.role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    permissions = collect_permissions(user)
    token = create_access_token(
        subject=user.id,
        role=user.role.name,
        extra_claims={
            "email": user.email,
            "risk_score": user.risk_score.score if user.risk_score else 0,
            "device_trust": user.risk_score.device_trust if user.risk_score else 100,
            "permissions": permissions,
        },
    )
    token_payload = decode_token(token)
    record_session(
        db,
        user_id=user.id,
        jwt_id=token_payload["jti"],
        device_id=payload.device_id,
        ip_address=payload.ip_address,
        user_agent=user_agent,
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/auth/bootstrap-admin", tags=["auth"])
def bootstrap_admin(db: Session = Depends(get_db)) -> dict:
    """Create the first administrative account in an empty environment."""
    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    if user_count > 0:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Bootstrap already completed")
    admin = bootstrap_admin_if_needed(db)
    return {
        "user_id": admin.id,
        "email": admin.email,
        "message": "Bootstrap admin created",
    }


@router.get("/auth/me", response_model=AuthenticatedUser, tags=["auth"])
def me(user: AuthenticatedUser = Depends(require_permission("dashboard:read"))) -> AuthenticatedUser:
    """Return the caller's resolved identity, tenant, and request risk context."""
    return user


@router.get("/auth/oauth/providers", tags=["auth"])
def oauth_providers() -> dict:
    """List placeholder OAuth integration targets for future identity federation work."""
    return {
        "providers": [
            {"name": "Azure AD", "status": "ready-for-integration"},
            {"name": "Google Workspace", "status": "ready-for-integration"},
            {"name": "Okta", "status": "ready-for-integration"},
        ]
    }


@router.get("/roles", tags=["roles"])
def roles(
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> dict:
    """Return the current RBAC role library for administrative review."""
    _ = user
    seed_roles_and_permissions(db)
    rows = db.scalars(select(Role).order_by(Role.name)).all()
    return {"items": [{"id": role.id, "name": role.name, "description": role.description} for role in rows]}


@router.get("/tenants/me", response_model=TenantResponse, tags=["tenants"])
def current_tenant(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> TenantResponse:
    """Return the tenant currently associated with the authenticated session."""
    tenant = db.scalar(select(Tenant).where(Tenant.id == user.tenant_id))
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse(id=tenant.id, organization_id=tenant.organization_id, name=tenant.name, status=tenant.status)


@router.post("/compliance/consent", response_model=ConsentRecordResponse, tags=["compliance"])
def capture_consent(
    payload: ConsentRequest,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> ConsentRecordResponse:
    """Record a consent decision for the authenticated user."""
    db_user = db.scalar(select(User).where(User.id == user.user_id))
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    record = record_consent(
        db,
        user=db_user,
        consent_type=payload.consent_type,
        consent_granted=payload.consent_granted,
        policy_version=payload.policy_version,
    )
    return ConsentRecordResponse(
        id=record.id,
        user_id=record.user_id,
        consent_type=record.consent_type,
        consent_granted=record.consent_granted,
        policy_version=record.policy_version,
        captured_at=record.captured_at,
    )


@router.get("/compliance/consents", response_model=list[ConsentRecordResponse], tags=["compliance"])
def consent_records(
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> list[ConsentRecordResponse]:
    """List tenant-scoped consent evidence for audit and privacy review."""
    _ = user
    rows = db.scalars(
        select(ConsentRecord).where(ConsentRecord.tenant_id == tenant_scope_id(user)).order_by(ConsentRecord.captured_at.desc()).limit(50)
    ).all()
    return [
        ConsentRecordResponse(
            id=row.id,
            user_id=row.user_id,
            consent_type=row.consent_type,
            consent_granted=row.consent_granted,
            policy_version=row.policy_version,
            captured_at=row.captured_at,
        )
        for row in rows
    ]


@router.get("/compliance/retention-policies", response_model=list[RetentionPolicyResponse], tags=["compliance"])
def retention_policies(
    user: AuthenticatedUser = Depends(require_permission("logs:read")),
    db: Session = Depends(get_db),
) -> list[RetentionPolicyResponse]:
    """Return configured data retention policies that support compliance review."""
    _ = user
    seed_retention_policies(db)
    rows = db.scalars(select(RetentionPolicy).order_by(RetentionPolicy.data_domain)).all()
    return [
        RetentionPolicyResponse(
            id=row.id,
            data_domain=row.data_domain,
            retention_days=row.retention_days,
            legal_basis=row.legal_basis,
            purge_strategy=row.purge_strategy,
        )
        for row in rows
    ]


@router.get("/dashboard", response_model=DashboardResponse, tags=["dashboard"])
def dashboard(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
) -> DashboardResponse:
    """Return the main SOC dashboard payload used by the frontend overview."""
    _ = user
    return DashboardResponse(**build_dashboard())


@router.get("/alerts", tags=["alerts"])
def alerts(
    user: AuthenticatedUser = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
) -> dict:
    """Return the active tenant alert feed, falling back to demo data if needed."""
    _ = user
    rows = db.scalars(select(Alert).where(Alert.tenant_id == tenant_scope_id(user)).order_by(Alert.created_at.desc()).limit(20)).all()
    if not rows:
        return {
            "items": [
                {
                    "id": item["id"],
                    "severity": item["severity"],
                    "title": item["title"],
                    "source": item["source"],
                    "timestamp": item.get("timestamp"),
                    "status": item["status"],
                }
                for item in build_dashboard()["alerts"]
            ]
        }
    return {"items": [serialize_alert(row) for row in rows]}


@router.get("/devices", response_model=list[DeviceItem], tags=["devices"])
def devices(user: AuthenticatedUser = Depends(require_permission("devices:read"))) -> list[DeviceItem]:
    """Return monitored device summaries for the dashboard."""
    _ = user
    return [DeviceItem(**device) for device in DEVICES]


@router.get("/incidents", response_model=list[IncidentItem], tags=["incidents"])
def incidents(
    user: AuthenticatedUser = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
) -> list[IncidentItem]:
    """List incident summaries for the current tenant."""
    _ = user
    rows = db.scalars(
        select(Incident).where(Incident.tenant_id == tenant_scope_id(user)).order_by(Incident.updated_at.desc()).limit(50)
    ).all()
    if not rows:
        return [IncidentItem(**incident) for incident in INCIDENTS]
    return [
        IncidentItem(
            id=row.id,
            title=row.title,
            severity=row.severity,
            owner=row.owner_user_id or "unassigned",
            status=row.status,
            response_stage=row.response_stage,
        )
        for row in rows
    ]


@router.post("/incidents", response_model=IncidentResponse, tags=["incidents"])
def create_incident(
    payload: IncidentCreate,
    user: AuthenticatedUser = Depends(require_permission("incidents:write")),
    db: Session = Depends(get_db),
) -> IncidentResponse:
    """Create a new incident ticket for a tenant-scoped investigation."""
    incident = create_incident_ticket(db, tenant_id=tenant_scope_id(user), payload=payload, owner_user_id=user.user_id)
    return incident_to_response(incident)


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse, tags=["incidents"])
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    user: AuthenticatedUser = Depends(require_permission("incidents:write")),
    db: Session = Depends(get_db),
) -> IncidentResponse:
    """Progress an incident through the response workflow and record notes."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_scope_id(user)))
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    incident = append_incident_activity(
        db,
        incident=incident,
        actor_user_id=user.user_id,
        activity_type="workflow_update",
        notes=payload.notes,
        status=payload.status,
        response_stage=payload.response_stage,
    )
    return incident_to_response(incident)


@router.get("/incidents/{incident_id}/activities", response_model=list[IncidentActivityItem], tags=["incidents"])
def incident_activities(
    incident_id: str,
    user: AuthenticatedUser = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
) -> list[IncidentActivityItem]:
    """Return the investigation timeline for a specific incident."""
    _ = user
    rows = db.scalars(
        select(IncidentActivity).where(IncidentActivity.incident_id == incident_id).order_by(IncidentActivity.created_at.desc())
    ).all()
    return [
        IncidentActivityItem(
            id=row.id,
            activity_type=row.activity_type,
            notes=row.notes,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.get("/incidents/dashboard/investigation", response_model=InvestigationDashboardResponse, tags=["incidents"])
def investigation_dashboard(
    user: AuthenticatedUser = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
) -> InvestigationDashboardResponse:
    """Return incident-response metrics for analyst investigation views."""
    _ = user
    return build_investigation_dashboard(db, tenant_scope_id(user))


@router.get("/risk/{user_id}", tags=["risk"])
def risk_profile(
    user_id: str,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
) -> RiskEvaluation:
    """Inspect the current risk decision context for a user."""
    if user_id != user.user_id and user.role == "Viewer":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Viewer cannot inspect peers")
    return RiskEvaluation(
        user_id=user_id,
        session_id=user.session_id,
        risk_score=user.request_risk_score,
        decision=user.zero_trust_decision,
        factors={
            "failed_logins": 3,
            "ip_reputation": 80,
            "device_trust": user.device_trust,
            "privilege_changes": 0,
            "session_status": user.session_status,
        },
    )


@router.get("/audit-logs", tags=["logs"])
def audit_logs(
    user: AuthenticatedUser = Depends(require_permission("logs:read")),
    db: Session = Depends(get_db),
) -> dict:
    """Return tenant-scoped audit logs for security review and compliance evidence."""
    _ = user
    rows = db.scalars(
        select(LogEntry).where(LogEntry.tenant_id == tenant_scope_id(user)).order_by(LogEntry.timestamp.desc()).limit(100)
    ).all()
    if not rows:
        return {"items": AUDIT_LOGS}
    return {
        "items": [
            {
                "timestamp": row.timestamp,
                "user_id": row.user_id,
                "ip_address": row.ip_address,
                "endpoint": row.endpoint,
                "action": row.action,
                "status": row.status,
                "metadata": row.metadata_json,
            }
            for row in rows
        ]
    }


@router.get("/compliance/report", response_model=ComplianceReportResponse, tags=["compliance"])
def compliance_report(
    user: AuthenticatedUser = Depends(require_permission("logs:read")),
    db: Session = Depends(get_db),
) -> ComplianceReportResponse:
    """Generate a tenant-scoped compliance summary for auditors or administrators."""
    _ = user
    return build_compliance_report(db, tenant_scope_id(user))


@router.get("/threats/analysis", response_model=ThreatAnalysisResponse, tags=["threats"])
def threat_analysis(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> ThreatAnalysisResponse:
    """Summarize recent threat activity, alert volume, and detection sources."""
    _ = user
    return build_threat_analysis(db, tenant_scope_id(user))


@router.get("/threats/events", response_model=list[ThreatEventItem], tags=["threats"])
def threat_events(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[ThreatEventItem]:
    """Return the most recent stored security events for analyst review."""
    _ = user
    rows = db.scalars(
        select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_scope_id(user)).order_by(SecurityEvent.created_at.desc()).limit(30)
    ).all()
    return [
        ThreatEventItem(
            id=row.id,
            event_type=row.event_type,
            severity=row.severity,
            source=row.source,
            created_at=row.created_at,
            summary=str(row.event_payload)[:180],
        )
        for row in rows
    ]


@router.get("/attack-graph", response_model=AttackGraphResponse, tags=["attack-graph"])
def attack_graph(
    incident_id: str | None = None,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> AttackGraphResponse:
    """
    Endpoint: GET /attack-graph

    Purpose:
    Return a real-time attack graph projection built from recent tenant events.

    Security:
    - Graph content is derived only from events already visible to the tenant.
    - An optional incident focus narrows the graph to a specific investigation.
    """
    return build_attack_graph(db, tenant_scope_id(user), incident_id=incident_id)


@router.post("/hunting/search", response_model=ThreatHuntSearchResponse, tags=["hunting"])
def hunt_search(
    payload: ThreatHuntSearchRequest,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> ThreatHuntSearchResponse:
    """
    Endpoint: POST /hunting/search

    Purpose:
    Run a proactive threat-hunting query over historical tenant-scoped events.

    Security:
    - Analysts use validated filters rather than raw query syntax.
    - Results remain isolated to the caller's tenant.
    """
    return run_threat_hunt(db, tenant_scope_id(user), payload)


@router.get("/hunting/saved-queries", response_model=list[SavedThreatHuntResponse], tags=["hunting"])
def saved_hunts(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[SavedThreatHuntResponse]:
    """Return saved hunt queries that analysts can reuse during investigations."""
    rows = db.scalars(
        select(ThreatHuntQuery)
        .where(ThreatHuntQuery.tenant_id == tenant_scope_id(user))
        .order_by(ThreatHuntQuery.updated_at.desc())
    ).all()
    return [
        SavedThreatHuntResponse(
            id=row.id,
            name=row.name,
            description=row.description,
            filters=row.filters or {},
            notes=row.notes,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


@router.post("/hunting/saved-queries", response_model=SavedThreatHuntResponse, tags=["hunting"])
def create_saved_hunt(
    payload: SavedThreatHuntCreate,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> SavedThreatHuntResponse:
    """Store a reusable threat-hunt query with analyst notes."""
    row = save_threat_hunt_query(db, tenant_id=tenant_scope_id(user), user_id=user.user_id, payload=payload)
    return SavedThreatHuntResponse(
        id=row.id,
        name=row.name,
        description=row.description,
        filters=row.filters or {},
        notes=row.notes,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/hunting/reports", response_model=list[ThreatHuntReportResponse], tags=["hunting"])
def hunt_reports(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[ThreatHuntReportResponse]:
    """List saved threat-hunting reports for handoff and audit review."""
    rows = db.scalars(
        select(ThreatHuntReport)
        .where(ThreatHuntReport.tenant_id == tenant_scope_id(user))
        .order_by(ThreatHuntReport.created_at.desc())
    ).all()
    return [
        ThreatHuntReportResponse(
            id=row.id,
            title=row.title,
            summary=row.summary,
            events_analyzed=row.events_analyzed,
            identified_threats=row.identified_threats or [],
            recommended_mitigations=row.recommended_mitigations or [],
            export_format=row.export_format,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post("/hunting/reports", response_model=ThreatHuntReportResponse, tags=["hunting"])
def create_hunt_report(
    payload: ThreatHuntReportCreate,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> ThreatHuntReportResponse:
    """Generate an exportable threat-hunting report from an investigation."""
    row = build_threat_hunt_report(db, tenant_id=tenant_scope_id(user), user_id=user.user_id, payload=payload)
    return ThreatHuntReportResponse(
        id=row.id,
        title=row.title,
        summary=row.summary,
        events_analyzed=row.events_analyzed,
        identified_threats=row.identified_threats or [],
        recommended_mitigations=row.recommended_mitigations or [],
        export_format=row.export_format,
        created_at=row.created_at,
    )


@router.post("/hunting/promote", response_model=ThreatHuntPromoteResponse, tags=["hunting"])
def promote_hunt(
    payload: ThreatHuntPromoteRequest,
    user: AuthenticatedUser = Depends(require_permission("incidents:write")),
    db: Session = Depends(get_db),
) -> ThreatHuntPromoteResponse:
    """Convert threat-hunting findings into an alert, incident, and case."""
    return promote_hunt_to_incident(db, tenant_id=tenant_scope_id(user), user_id=user.user_id, payload=payload)


@router.get("/sessions", response_model=list[SessionItem], tags=["sessions"])
def sessions(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[SessionItem]:
    """List live and recent sessions that belong to the current tenant."""
    statement = select(UserSession).where(UserSession.tenant_id == tenant_scope_id(user)).order_by(UserSession.last_seen.desc())
    if user.role == "Viewer":
        statement = statement.where(UserSession.user_id == user.user_id)
    rows = db.scalars(statement).all()
    return [
        SessionItem(
            session_id=session.id,
            user_id=session.user_id,
            ip_address=session.ip_address or "unknown",
            device_id=session.device_id,
            status=session.status,
            last_seen=session.last_seen,
        )
        for session in rows
    ]


@router.post("/ingestion/events", response_model=IngestEventResponse, tags=["ingestion"])
def ingest_event(
    payload: IngestEventRequest,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> IngestEventResponse:
    """
    Endpoint: POST /ingestion/events

    Purpose:
    Accept telemetry, normalize it, enrich it, evaluate threat intelligence, and
    optionally correlate it into a broader incident.

    Security:
    - Protected by the normal authenticated API controls in this MVP.
    - In larger deployments this would sit behind a dedicated collector path.
    """
    normalized = normalize_event(payload.payload | {"source_type": payload.source_type})
    enriched = enrich_event(normalized)
    intel_matches = evaluate_threat_intel(db, tenant_scope_id(user), enriched)
    # Persist the normalized event so later detections, correlations, and
    # incident workflows can refer back to the original evidence.
    event = SecurityEvent(
        tenant_id=tenant_scope_id(user),
        user_id=user.user_id,
        event_type=enriched["event_type"],
        severity=enriched["severity"],
        source=f"{payload.source_type}-collector",
        event_payload=enriched,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    ai_score = score_event(db, tenant_scope_id(user), event)
    persist_ai_finding(db, tenant_scope_id(user), event, ai_score)
    correlation = correlate_recent_events(db, tenant_scope_id(user))
    return IngestEventResponse(
        normalized_event=enriched,
        intel_matches=[match.indicator_value for match in intel_matches],
        correlated_incident=correlation.incident_id if correlation else None,
        ai_result={
            "anomaly_detected": ai_score.anomaly_detected,
            "anomaly_type": ai_score.anomaly_type,
            "confidence_score": ai_score.confidence_score,
            "risk_score": ai_score.risk_score,
            "severity": ai_score.severity,
            "recommended_action": ai_score.recommended_action,
            "details": ai_score.details,
        },
    )


@router.post("/ingestion/endpoint", response_model=IngestEventResponse, tags=["ingestion"])
def ingest_endpoint_event(
    payload: IngestEventRequest,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> IngestEventResponse:
    """Endpoint-specific alias used by the lightweight endpoint agent scaffold."""
    return ingest_event(payload, user, db)


@router.post("/ai/train", response_model=AITrainingResponse, tags=["ai"])
def train_ai_models(
    payload: AITrainingRequest,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> AITrainingResponse:
    """
    Endpoint: POST /ai/train

    Purpose:
    Train or refresh the tenant's anomaly-detection model using historical
    events already stored in the platform.

    Security:
    - Restricted to administrative users because retraining changes how future
      detections are interpreted.
    - Training remains tenant-scoped so behavior from one organization never
      influences another organization's model.
    """
    trained, sample_count, model_version = train_models(db, tenant_scope_id(user), payload.lookback_hours)
    return AITrainingResponse(
        trained=trained,
        sample_count=sample_count,
        model_version=model_version,
        lookback_hours=payload.lookback_hours,
    )


@router.get("/ai/findings", response_model=list[AIFindingResponse], tags=["ai"])
def ai_findings(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[AIFindingResponse]:
    """
    Endpoint: GET /ai/findings

    Purpose:
    Return recent AI anomaly findings so analysts can inspect model-driven
    detections alongside rule-based alerts.

    Security:
    - Findings are tenant-scoped.
    - Viewers can read findings but cannot retrain models or alter rules.
    """
    rows = db.scalars(
        select(AIAnomalyFinding)
        .where(AIAnomalyFinding.tenant_id == tenant_scope_id(user))
        .order_by(AIAnomalyFinding.created_at.desc())
        .limit(50)
    ).all()
    return [
        AIFindingResponse(
            id=row.id,
            event_id=row.event_id,
            anomaly_type=row.anomaly_type,
            confidence_score=row.confidence_score,
            risk_score=row.risk_score,
            severity=row.severity,
            recommended_action=row.recommended_action,
            device_id=row.device_id,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.get("/ai/risk/{user_id}", response_model=AIScoreResponse, tags=["ai"])
def ai_risk_summary(
    user_id: str,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> AIScoreResponse:
    """
    Endpoint: GET /ai/risk/{user_id}

    Purpose:
    Summarize recent AI-driven risk associated with a specific user identity.

    Security:
    - Viewers are limited to their own identity to avoid unnecessary peer
      monitoring access.
    """
    if user.role == "Viewer" and user.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Viewer cannot inspect peers")
    rows = db.scalars(
        select(AIAnomalyFinding)
        .where(AIAnomalyFinding.tenant_id == tenant_scope_id(user), AIAnomalyFinding.user_id == user_id)
        .order_by(AIAnomalyFinding.created_at.desc())
        .limit(10)
    ).all()
    highest_score = max((row.risk_score for row in rows), default=0)
    highest_confidence = max((row.confidence_score for row in rows), default=0)
    latest = rows[0] if rows else None
    return AIScoreResponse(
        user_id=user_id,
        risk_score=highest_score,
        risk_level="Critical" if highest_score >= 85 else "High" if highest_score >= 65 else "Moderate" if highest_score >= 40 else "Low",
        confidence_score=highest_confidence,
        anomaly_type=latest.anomaly_type if latest else "no-recent-anomalies",
        recommended_action=latest.recommended_action if latest else "Continue baseline monitoring.",
    )


@router.get("/stream/alerts", tags=["stream"])
async def stream_alerts(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """
    Endpoint: GET /stream/alerts

    Purpose:
    Stream alert and AI finding updates to the dashboard using Server-Sent
    Events. This keeps the UI responsive without requiring page refreshes.

    Security:
    - The stream is authenticated and tenant-scoped.
    - Only high-level alerting data is emitted; sensitive evidence stays behind
      normal detail endpoints and RBAC checks.
    """

    async def event_generator() -> str:
        while True:
            alert_rows = db.scalars(
                select(Alert)
                .where(Alert.tenant_id == tenant_scope_id(user))
                .order_by(Alert.created_at.desc())
                .limit(5)
            ).all()
            finding_rows = db.scalars(
                select(AIAnomalyFinding)
                .where(AIAnomalyFinding.tenant_id == tenant_scope_id(user))
                .order_by(AIAnomalyFinding.created_at.desc())
                .limit(5)
            ).all()
            graph = build_attack_graph(db, tenant_scope_id(user), limit=60)
            payload = {
                "alerts": [serialize_alert(row) for row in alert_rows],
                "ai_findings": [
                    {
                        "id": row.id,
                        "event_id": row.event_id,
                        "anomaly_type": row.anomaly_type,
                        "confidence_score": row.confidence_score,
                        "risk_score": row.risk_score,
                        "severity": row.severity,
                        "recommended_action": row.recommended_action,
                        "device_id": row.device_id,
                        "created_at": row.created_at.isoformat() if row.created_at else None,
                    }
                    for row in finding_rows
                ],
                "attack_graph": graph.model_dump(mode="json"),
            }
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/correlations", response_model=list[CorrelationResponse], tags=["correlation"])
def correlations(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[CorrelationResponse]:
    """Return recent correlation results created by the SIEM correlation engine."""
    rows = db.scalars(
        select(CorrelationRecord).where(CorrelationRecord.tenant_id == tenant_scope_id(user)).order_by(CorrelationRecord.created_at.desc()).limit(30)
    ).all()
    return [
        CorrelationResponse(
            id=row.id,
            correlation_name=row.correlation_name,
            event_ids=row.event_ids,
            incident_id=row.incident_id,
            severity=row.severity,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post("/correlations/run", response_model=CorrelationResponse | None, tags=["correlation"])
def run_correlation(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> CorrelationResponse | None:
    """Execute the simple MVP correlation pass against recent tenant events."""
    row = correlate_recent_events(db, tenant_scope_id(user))
    if not row:
        return None
    return CorrelationResponse(
        id=row.id,
        correlation_name=row.correlation_name,
        event_ids=row.event_ids,
        incident_id=row.incident_id,
        severity=row.severity,
        created_at=row.created_at,
    )


@router.get("/rules", response_model=list[DetectionRuleResponse], tags=["rules"])
def rules(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[DetectionRuleResponse]:
    """List tenant detection rules, including MITRE ATT&CK mapping fields."""
    seed_soc_modules(db, tenant_scope_id(user))
    rows = db.scalars(select(DetectionRule).where(DetectionRule.tenant_id == tenant_scope_id(user)).order_by(DetectionRule.rule_name)).all()
    return [
        DetectionRuleResponse(
            id=row.id,
            rule_name=row.rule_name,
            severity_level=row.severity_level,
            response_action=row.response_action,
            tactic=row.tactic,
            technique=row.technique,
            mitre_technique_id=row.mitre_technique_id,
            is_active=row.is_active,
        )
        for row in rows
    ]


@router.post("/rules", response_model=DetectionRuleResponse, tags=["rules"])
def create_rule(
    payload: DetectionRuleCreate,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> DetectionRuleResponse:
    """Create a new tenant-scoped detection rule."""
    row = DetectionRule(tenant_id=tenant_scope_id(user), **payload.model_dump(), is_active=True)
    db.add(row)
    db.commit()
    db.refresh(row)
    return DetectionRuleResponse(
        id=row.id,
        rule_name=row.rule_name,
        severity_level=row.severity_level,
        response_action=row.response_action,
        tactic=row.tactic,
        technique=row.technique,
        mitre_technique_id=row.mitre_technique_id,
        is_active=row.is_active,
    )


@router.patch("/rules/{rule_id}/toggle", response_model=DetectionRuleResponse, tags=["rules"])
def toggle_rule(
    rule_id: str,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> DetectionRuleResponse:
    """Activate or deactivate a detection rule without deleting it."""
    row = db.scalar(select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant_scope_id(user)))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    row.is_active = not row.is_active
    db.commit()
    db.refresh(row)
    return DetectionRuleResponse(
        id=row.id,
        rule_name=row.rule_name,
        severity_level=row.severity_level,
        response_action=row.response_action,
        tactic=row.tactic,
        technique=row.technique,
        mitre_technique_id=row.mitre_technique_id,
        is_active=row.is_active,
    )


@router.post("/rules/{rule_id}/test", response_model=RuleTestResponse, tags=["rules"])
def test_detection_rule(
    rule_id: str,
    payload: RuleTestRequest,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> RuleTestResponse:
    """Run a detection rule in a sandbox so analysts can validate rule behavior safely."""
    row = db.scalar(select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant_scope_id(user)))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return test_rule(row, payload.event_payload)


@router.get("/mitre/mappings", tags=["mitre"])
def mitre_mappings(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> dict:
    """Return MITRE ATT&CK mappings derived from the detection rule library."""
    rows = db.scalars(select(DetectionRule).where(DetectionRule.tenant_id == tenant_scope_id(user)).order_by(DetectionRule.rule_name)).all()
    return {
        "items": [
            {
                "rule_id": row.id,
                "rule_name": row.rule_name,
                "tactic": row.tactic,
                "technique": row.technique,
                "mitre_technique_id": row.mitre_technique_id,
            }
            for row in rows
        ]
    }


@router.get("/threat-intel", response_model=list[ThreatIntelResponse], tags=["threat-intel"])
def threat_intel(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[ThreatIntelResponse]:
    """Return the tenant's threat intelligence indicators."""
    seed_soc_modules(db, tenant_scope_id(user))
    rows = db.scalars(
        select(ThreatIntelIndicator).where(ThreatIntelIndicator.tenant_id == tenant_scope_id(user)).order_by(ThreatIntelIndicator.created_at.desc())
    ).all()
    return [
        ThreatIntelResponse(
            id=row.id,
            indicator_type=row.indicator_type,
            indicator_value=row.indicator_value,
            provider=row.provider,
            confidence=row.confidence,
            status=row.status,
        )
        for row in rows
    ]


@router.get("/gateway/status", tags=["gateway"])
def gateway_status(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
) -> dict:
    """Expose the current API security gateway posture for the authenticated session."""
    return {
        "tenant_id": user.tenant_id,
        "jwt_authentication": "enabled",
        "rate_limiting": "enabled",
        "request_validation": "enabled",
        "api_threat_detection": "enabled",
        "session_status": user.session_status,
        "zero_trust_decision": user.zero_trust_decision,
    }


@router.post("/threat-intel", response_model=ThreatIntelResponse, tags=["threat-intel"])
def create_threat_intel(
    payload: ThreatIntelCreate,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> ThreatIntelResponse:
    """Add a new tenant-scoped threat intelligence indicator."""
    row = ThreatIntelIndicator(tenant_id=tenant_scope_id(user), **payload.model_dump(), status="Active")
    db.add(row)
    db.commit()
    db.refresh(row)
    return ThreatIntelResponse(
        id=row.id,
        indicator_type=row.indicator_type,
        indicator_value=row.indicator_value,
        provider=row.provider,
        confidence=row.confidence,
        status=row.status,
    )


@router.get("/cases", response_model=list[CaseResponse], tags=["cases"])
def cases(
    user: AuthenticatedUser = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
) -> list[CaseResponse]:
    """List investigation cases associated with the current tenant."""
    rows = db.scalars(select(CaseRecord).where(CaseRecord.tenant_id == tenant_scope_id(user)).order_by(CaseRecord.updated_at.desc())).all()
    return [
        CaseResponse(
            id=row.id,
            incident_reference=row.incident_reference,
            assigned_analyst=row.assigned_analyst,
            investigation_notes=row.investigation_notes,
            evidence_files=row.evidence_files,
            status=row.status,
            resolution_summary=row.resolution_summary,
            updated_at=row.updated_at,
        )
        for row in rows
    ]


@router.post("/cases", response_model=CaseResponse, tags=["cases"])
def create_case_record(
    payload: CaseCreate,
    user: AuthenticatedUser = Depends(require_permission("incidents:write")),
    db: Session = Depends(get_db),
) -> CaseResponse:
    """Open a new investigation case, optionally linked to an incident."""
    row = create_case(
        db,
        tenant_id=tenant_scope_id(user),
        incident_reference=payload.incident_reference,
        assigned_analyst=payload.assigned_analyst or user.user_id,
        investigation_notes=payload.investigation_notes,
        evidence_files=payload.evidence_files,
    )
    return CaseResponse(
        id=row.id,
        incident_reference=row.incident_reference,
        assigned_analyst=row.assigned_analyst,
        investigation_notes=row.investigation_notes,
        evidence_files=row.evidence_files,
        status=row.status,
        resolution_summary=row.resolution_summary,
        updated_at=row.updated_at,
    )


@router.patch("/cases/{case_id}", response_model=CaseResponse, tags=["cases"])
def update_case_record(
    case_id: str,
    payload: CaseUpdate,
    user: AuthenticatedUser = Depends(require_permission("incidents:write")),
    db: Session = Depends(get_db),
) -> CaseResponse:
    """Update investigation notes, lifecycle state, or resolution details for a case."""
    row = db.scalar(select(CaseRecord).where(CaseRecord.id == case_id, CaseRecord.tenant_id == tenant_scope_id(user)))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    row = update_case(db, row, notes=payload.investigation_notes, status=payload.status, resolution_summary=payload.resolution_summary)
    return CaseResponse(
        id=row.id,
        incident_reference=row.incident_reference,
        assigned_analyst=row.assigned_analyst,
        investigation_notes=row.investigation_notes,
        evidence_files=row.evidence_files,
        status=row.status,
        resolution_summary=row.resolution_summary,
        updated_at=row.updated_at,
    )


@router.get("/playbooks", response_model=list[PlaybookResponse], tags=["playbooks"])
def playbooks(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[PlaybookResponse]:
    """List the tenant's response automation playbooks."""
    seed_soc_modules(db, tenant_scope_id(user))
    rows = db.scalars(select(AutomationPlaybook).where(AutomationPlaybook.tenant_id == tenant_scope_id(user))).all()
    return [
        PlaybookResponse(
            id=row.id,
            name=row.name,
            trigger_event=row.trigger_event,
            steps=row.steps,
            requires_approval=row.requires_approval,
            is_active=row.is_active,
        )
        for row in rows
    ]


@router.post("/playbooks", response_model=PlaybookResponse, tags=["playbooks"])
def create_playbook(
    payload: PlaybookCreate,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> PlaybookResponse:
    """Create a new SOAR-style playbook definition."""
    row = AutomationPlaybook(tenant_id=tenant_scope_id(user), **payload.model_dump(), is_active=True)
    db.add(row)
    db.commit()
    db.refresh(row)
    return PlaybookResponse(
        id=row.id,
        name=row.name,
        trigger_event=row.trigger_event,
        steps=row.steps,
        requires_approval=row.requires_approval,
        is_active=row.is_active,
    )


@router.post("/playbooks/{playbook_id}/execute", response_model=PlaybookExecutionResponse, tags=["playbooks"])
def execute_playbook_route(
    playbook_id: str,
    user: AuthenticatedUser = Depends(require_permission("incidents:write")),
    db: Session = Depends(get_db),
) -> PlaybookExecutionResponse:
    """Return the steps that would execute for a given playbook trigger."""
    row = db.scalar(select(AutomationPlaybook).where(AutomationPlaybook.id == playbook_id, AutomationPlaybook.tenant_id == tenant_scope_id(user)))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    executed_steps = execute_playbook(db, row)
    return PlaybookExecutionResponse(
        playbook_id=row.id,
        trigger_event=row.trigger_event,
        execution_mode="awaiting-approval" if row.requires_approval else "automated",
        executed_steps=executed_steps,
    )


@router.get("/posture", response_model=list[PostureSnapshotResponse], tags=["posture"])
def posture_snapshots(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[PostureSnapshotResponse]:
    """List stored posture measurements for the current tenant."""
    rows = db.scalars(select(PostureSnapshot).where(PostureSnapshot.tenant_id == tenant_scope_id(user)).order_by(PostureSnapshot.created_at.desc())).all()
    return [
        PostureSnapshotResponse(
            id=row.id,
            environment_name=row.environment_name,
            patch_status=row.patch_status,
            vulnerable_software=row.vulnerable_software,
            inactive_security_controls=row.inactive_security_controls,
            unsecured_services=row.unsecured_services,
            posture_score=row.posture_score,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post("/posture", response_model=PostureSnapshotResponse, tags=["posture"])
def create_posture(
    payload: PostureSnapshotCreate,
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> PostureSnapshotResponse:
    """Store a new security posture snapshot for an environment."""
    row = create_posture_snapshot(db, tenant_id=tenant_scope_id(user), **payload.model_dump())
    return PostureSnapshotResponse(
        id=row.id,
        environment_name=row.environment_name,
        patch_status=row.patch_status,
        vulnerable_software=row.vulnerable_software,
        inactive_security_controls=row.inactive_security_controls,
        unsecured_services=row.unsecured_services,
        posture_score=row.posture_score,
        created_at=row.created_at,
    )


@router.get("/simulations", response_model=list[SimulationResponse], tags=["simulations"])
def simulations(
    user: AuthenticatedUser = Depends(require_permission("dashboard:read")),
    db: Session = Depends(get_db),
) -> list[SimulationResponse]:
    """List Cyber Attack Simulation Lab runs for the current tenant."""
    rows = db.scalars(select(RedTeamSimulation).where(RedTeamSimulation.tenant_id == tenant_scope_id(user)).order_by(RedTeamSimulation.created_at.desc())).all()
    return [serialize_simulation(row) for row in rows]


@router.post("/simulations", response_model=SimulationResponse, tags=["simulations"])
def create_simulation_route(
    payload: SimulationCreate,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> SimulationResponse:
    """
    Create a simulation scenario and execute it immediately unless scheduled.

    This endpoint is the primary entry point for the Cyber Attack Simulation
    Lab. It keeps safety metadata attached to the simulation record and ensures
    simulated telemetry flows into the same detection stack as production-style
    events.
    """
    row = create_simulation_record(db, tenant_id=tenant_scope_id(user), payload=payload)
    if payload.mode != "scheduled":
        row = execute_simulation(db, simulation=row, actor_user_id=user.user_id)
    return serialize_simulation(row)


@router.post("/simulations/{simulation_id}/start", response_model=SimulationControlResponse, tags=["simulations"])
def start_simulation_route(
    simulation_id: str,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> SimulationControlResponse:
    """Start a previously scheduled or planned lab simulation."""
    row = db.scalar(select(RedTeamSimulation).where(RedTeamSimulation.id == simulation_id, RedTeamSimulation.tenant_id == tenant_scope_id(user)))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation not found")
    if row.status == "Completed":
        return SimulationControlResponse(simulation_id=row.id, status=row.status, message="Simulation already completed")
    if row.status == "Stopped":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Stopped simulations cannot be restarted")
    row = execute_simulation(db, simulation=row, actor_user_id=user.user_id)
    return SimulationControlResponse(simulation_id=row.id, status=row.status, message="Simulation executed successfully")


@router.post("/simulations/{simulation_id}/stop", response_model=SimulationControlResponse, tags=["simulations"])
def stop_simulation_route(
    simulation_id: str,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> SimulationControlResponse:
    """Stop a scheduled or pending simulation in the lab environment."""
    row = db.scalar(select(RedTeamSimulation).where(RedTeamSimulation.id == simulation_id, RedTeamSimulation.tenant_id == tenant_scope_id(user)))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation not found")
    if row.status == "Completed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Completed simulations cannot be stopped")
    row = stop_simulation(db, simulation=row)
    return SimulationControlResponse(simulation_id=row.id, status=row.status, message="Simulation stopped")


@router.post("/compliance/data-deletion", response_model=DeletionResponse, tags=["compliance"])
def data_deletion(
    payload: DeletionRequest,
    user: AuthenticatedUser = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
) -> DeletionResponse:
    """Mark a tenant-scoped user's data for deletion handling."""
    deleted = delete_user_data(db, tenant_id=tenant_scope_id(user), user_id=payload.user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return DeletionResponse(user_id=payload.user_id, tenant_id=tenant_scope_id(user), status="scheduled-for-deletion")
