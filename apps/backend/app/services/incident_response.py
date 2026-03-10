"""
SOC-CyBe Security Platform
Module: Incident Response Service

Purpose:
This module implements incident ticket creation, workflow updates, timeline
entries, and investigation dashboard summaries.

Security Considerations:
- Response actions must leave a trail because incidents often become audit or
  legal evidence.
- Status and stage are kept separate so analysts can express both business
  state and response progress.
"""

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import Incident, IncidentActivity
from app.schemas.incidents import IncidentCreate, IncidentResponse, InvestigationDashboardResponse


def incident_to_response(incident: Incident) -> IncidentResponse:
    """Convert an ORM incident into the API shape expected by clients."""
    created_at = incident.created_at if incident.created_at.tzinfo else incident.created_at.replace(tzinfo=timezone.utc)
    updated_at = incident.updated_at if incident.updated_at.tzinfo else incident.updated_at.replace(tzinfo=timezone.utc)
    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        response_stage=incident.response_stage,
        affected_asset=incident.affected_asset,
        owner_user_id=incident.owner_user_id,
        created_at=created_at,
        updated_at=updated_at,
    )


def create_incident_ticket(
    db: Session,
    *,
    tenant_id: str | None,
    payload: IncidentCreate,
    owner_user_id: str,
) -> Incident:
    """
    Open a new incident and record its first timeline activity.

    The initial activity entry matters because it anchors the investigation
    timeline from the moment the ticket is created.
    """
    now = datetime.utcnow()
    incident = Incident(
        tenant_id=tenant_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status="Open",
        response_stage="Identification",
        affected_asset=payload.affected_asset,
        owner_user_id=owner_user_id,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    db.add(
        IncidentActivity(
            incident_id=incident.id,
            actor_user_id=owner_user_id,
            activity_type="ticket_created",
            notes=f"Incident opened for asset {payload.affected_asset}",
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


def append_incident_activity(
    db: Session,
    *,
    incident: Incident,
    actor_user_id: str,
    activity_type: str,
    notes: str,
    status: str | None = None,
    response_stage: str | None = None,
) -> Incident:
    """Apply a workflow change to an incident and append a timeline entry."""
    if status:
        incident.status = status
    if response_stage:
        incident.response_stage = response_stage
    incident.updated_at = datetime.utcnow()
    db.add(
        IncidentActivity(
            incident_id=incident.id,
            actor_user_id=actor_user_id,
            activity_type=activity_type,
            notes=notes,
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


def build_investigation_dashboard(db: Session, tenant_id: str | None) -> InvestigationDashboardResponse:
    """Summarize active incident response activity for dashboard consumption."""
    open_incidents = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id, Incident.status.in_(["Open", "Investigating", "Contained"]))
    ) or 0
    critical_incidents = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id, Incident.severity == "Critical", Incident.status != "Closed")
    ) or 0
    containment_stage = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id, Incident.response_stage == "Containment", Incident.status != "Closed")
    ) or 0
    containment_rows = db.scalars(
        select(Incident).where(Incident.tenant_id == tenant_id, Incident.response_stage.in_(["Containment", "Eradication", "Recovery", "Lessons Learned"]))
    ).all()
    mtc = 0
    if containment_rows:
        mtc = int(
            sum(max(0, int((incident.updated_at - incident.created_at).total_seconds() // 60)) for incident in containment_rows)
            / len(containment_rows)
        )
    tickets = db.scalars(select(Incident).where(Incident.tenant_id == tenant_id).order_by(Incident.updated_at.desc()).limit(6)).all()
    return InvestigationDashboardResponse(
        open_incidents=open_incidents,
        critical_incidents=critical_incidents,
        containment_stage=containment_stage,
        mean_time_to_contain_minutes=mtc,
        active_tickets=[incident_to_response(ticket) for ticket in tickets],
    )
