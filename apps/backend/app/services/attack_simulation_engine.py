"""
SOC-CyBe Security Platform
Module: Attack Simulation Engine

Purpose:
This module powers the Cyber Attack Simulation Lab. It creates safe, isolated
attack scenarios that look realistic to the SOC pipeline without interacting
with real production infrastructure.

Architecture Notes:
- Simulated attacks are converted into normalized security events so they flow
  through the same AI, alerting, correlation, and incident-response layers
  used for live telemetry.
- The engine is intentionally deterministic enough for training, but it can
  randomize details when analysts want to exercise detections with varied
  inputs.

Safety Notes:
- Simulations are marked as lab-only and isolated in every stored record.
- The engine never executes real malware or offensive actions. It only emits
  telemetry representing what those actions would look like to a defender.
- Incident creation and playbook execution remain within SOC-CyBe's internal
  workflow so the lab is useful without touching external systems.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Alert, AutomationPlaybook, RedTeamSimulation, SecurityEvent
from app.schemas.incidents import IncidentCreate
from app.schemas.operations import SimulationCreate
from app.services.ai_detection_engine import persist_ai_finding, score_event
from app.services.incident_response import append_incident_activity, create_incident_ticket
from app.services.soc_operations import correlate_recent_events, evaluate_threat_intel, execute_playbook


INTENSITY_COUNTS = {
    "Low": 4,
    "Medium": 7,
    "High": 10,
}

SCENARIO_LIBRARY = {
    "brute_force": {
        "expected_detection": "Brute force login threshold exceeded and account compromise risk elevated.",
        "severity": "High",
        "playbook_trigger": "credential_attack_detected",
    },
    "suspicious_login_location": {
        "expected_detection": "AI anomaly engine flags impossible travel and unusual login behavior.",
        "severity": "High",
        "playbook_trigger": "identity_anomaly_detected",
    },
    "privilege_escalation": {
        "expected_detection": "Privilege escalation alert generated for unauthorized role modification.",
        "severity": "Critical",
        "playbook_trigger": "privilege_escalation_detected",
    },
    "malicious_file_execution": {
        "expected_detection": "Endpoint anomaly alert generated for suspicious process and file activity.",
        "severity": "Critical",
        "playbook_trigger": "malware_detected",
    },
    "data_exfiltration": {
        "expected_detection": "Data exfiltration warning generated for unusual download and outbound connection volume.",
        "severity": "Critical",
        "playbook_trigger": "data_exfiltration_detected",
    },
}


def _now() -> datetime:
    """Return a timezone-aware timestamp for simulation timeline generation."""
    return datetime.now(timezone.utc)


def _random_choice(values: list[str]) -> str:
    """Pick a value for randomized scenarios without exposing external state."""
    return random.choice(values)


def _build_scenario_events(payload: SimulationCreate) -> list[dict]:
    """
    Build a timeline of synthetic security events for the selected scenario.

    Each event mirrors the kind of payload the detection pipeline would ingest
    from collectors, API gateways, or endpoint telemetry.
    """
    start = payload.scheduled_for or _now()
    count = INTENSITY_COUNTS[payload.intensity_level]
    target_user = payload.target_user or "analyst.training@soc-cybe.lab"
    target_device = payload.target_device or "lab-endpoint-01"
    base_ip = _random_choice(["203.0.113.17", "198.51.100.42", "192.0.2.61"]) if payload.mode == "randomized" else "203.0.113.17"
    normal_location = "Johannesburg"
    foreign_location = _random_choice(["Frankfurt", "Singapore", "Sao Paulo"]) if payload.mode == "randomized" else "Frankfurt"

    if payload.scenario_type == "brute_force":
        return [
            {
                "timestamp": (start + timedelta(seconds=index * 8)).isoformat(),
                "event_type": "failed_login",
                "source_type": "application",
                "username": target_user,
                "source_ip": base_ip,
                "device_id": target_device,
                "count": index + 1,
                "severity": "High" if index + 1 >= 4 else "Medium",
                "description": f"Repeated login failure {index + 1} against lab identity.",
                "phase": "Credential Attack",
            }
            for index in range(count)
        ] + [
            {
                "timestamp": (start + timedelta(seconds=count * 8 + 10)).isoformat(),
                "event_type": "account_lockout_attempt",
                "source_type": "application",
                "username": target_user,
                "source_ip": base_ip,
                "device_id": target_device,
                "count": count,
                "severity": "High",
                "description": "Simulated account lockout threshold reached.",
                "phase": "Credential Attack",
            }
        ]

    if payload.scenario_type == "suspicious_login_location":
        return [
            {
                "timestamp": start.isoformat(),
                "event_type": "login",
                "source_type": "application",
                "username": target_user,
                "source_ip": "196.44.1.10",
                "device_id": target_device,
                "location": normal_location,
                "severity": "Low",
                "description": "Baseline login from typical geography.",
                "phase": "Initial Access",
            },
            {
                "timestamp": (start + timedelta(minutes=payload.duration_minutes)).isoformat(),
                "event_type": "login",
                "source_type": "application",
                "username": target_user,
                "source_ip": base_ip,
                "device_id": target_device,
                "location": foreign_location,
                "count": count,
                "severity": "High",
                "description": "Impossible-travel login from lab-generated foreign source.",
                "phase": "Initial Access",
            },
        ]

    if payload.scenario_type == "privilege_escalation":
        return [
            {
                "timestamp": start.isoformat(),
                "event_type": "user_role_change",
                "source_type": "application",
                "username": target_user,
                "actor_role": "Viewer",
                "requested_role": "Admin",
                "device_id": target_device,
                "source_ip": base_ip,
                "severity": "Critical",
                "description": "Unauthorized attempt to assign administrative privileges.",
                "phase": "Privilege Escalation",
            },
            {
                "timestamp": (start + timedelta(seconds=30)).isoformat(),
                "event_type": "privilege_change_request",
                "source_type": "application",
                "username": target_user,
                "device_id": target_device,
                "source_ip": base_ip,
                "count": count,
                "severity": "High",
                "description": "Follow-up permission modification request in lab environment.",
                "phase": "Privilege Escalation",
            },
        ]

    if payload.scenario_type == "malicious_file_execution":
        return [
            {
                "timestamp": start.isoformat(),
                "event_type": "process_creation",
                "source_type": "endpoint",
                "username": target_user,
                "device_id": target_device,
                "source_ip": base_ip,
                "process_name": "unknown_updater.exe",
                "severity": "High",
                "description": "Unsigned executable launched inside lab endpoint.",
                "phase": "Execution",
            },
            {
                "timestamp": (start + timedelta(seconds=20)).isoformat(),
                "event_type": "file_modification",
                "source_type": "endpoint",
                "username": target_user,
                "device_id": target_device,
                "source_ip": base_ip,
                "file_path": "/tmp/lab/persistence.conf",
                "count": count,
                "severity": "High",
                "description": "Suspicious file modification representing persistence behavior.",
                "phase": "Persistence",
            },
            {
                "timestamp": (start + timedelta(seconds=40)).isoformat(),
                "event_type": "device_anomaly",
                "source_type": "endpoint",
                "username": target_user,
                "device_id": target_device,
                "source_ip": base_ip,
                "severity": "Critical",
                "description": "Endpoint behavior deviates from expected baseline.",
                "phase": "Execution",
            },
        ]

    return [
        {
            "timestamp": start.isoformat(),
            "event_type": "database_access",
            "source_type": "application",
            "username": target_user,
            "device_id": target_device,
            "source_ip": base_ip,
            "count": count * 20,
            "severity": "High",
            "description": "Large-volume data access initiated in simulation lab.",
            "phase": "Collection",
        },
        {
            "timestamp": (start + timedelta(seconds=30)).isoformat(),
            "event_type": "file_download",
            "source_type": "application",
            "username": target_user,
            "device_id": target_device,
            "source_ip": base_ip,
            "count": count * 10,
            "severity": "High",
            "description": "Bulk file download activity simulated for data staging.",
            "phase": "Collection",
        },
        {
            "timestamp": (start + timedelta(seconds=55)).isoformat(),
            "event_type": "external_connection",
            "source_type": "network",
            "username": target_user,
            "device_id": target_device,
            "source_ip": base_ip,
            "destination_ip": "185.220.101.1",
            "count": count * 8,
            "severity": "Critical",
            "description": "Outbound transfer toward lab-designated exfiltration indicator.",
            "phase": "Exfiltration",
        },
    ]


def _simulation_to_timeline_entry(event_payload: dict, event_id: str, ai_risk: int, alert_titles: list[str]) -> dict:
    """Convert a stored event into a timeline item shown in the simulation lab."""
    return {
        "timestamp": event_payload.get("timestamp"),
        "phase": event_payload.get("phase", "Detection"),
        "event_type": event_payload.get("event_type"),
        "description": event_payload.get("description"),
        "event_id": event_id,
        "ai_risk_score": ai_risk,
        "alerts": alert_titles,
    }


def _find_playbook(db: Session, tenant_id: str | None, trigger_event: str) -> AutomationPlaybook | None:
    """Look up the playbook associated with a simulated detection trigger."""
    return db.scalar(
        select(AutomationPlaybook).where(
            AutomationPlaybook.tenant_id == tenant_id,
            AutomationPlaybook.trigger_event == trigger_event,
            AutomationPlaybook.is_active.is_(True),
        )
    )


def create_simulation_record(db: Session, *, tenant_id: str | None, payload: SimulationCreate) -> RedTeamSimulation:
    """
    Create a simulation record before it is executed.

    Scheduled simulations use this path so analysts can review configuration
    and launch timing before synthetic telemetry is emitted.
    """
    library_entry = SCENARIO_LIBRARY[payload.scenario_type]
    simulation = RedTeamSimulation(
        tenant_id=tenant_id,
        scenario_name=payload.scenario_name,
        scenario_type=payload.scenario_type,
        mode=payload.mode,
        intensity_level=payload.intensity_level,
        duration_minutes=payload.duration_minutes,
        target_user=payload.target_user,
        target_device=payload.target_device,
        training_mode=payload.training_mode,
        scheduled_for=payload.scheduled_for,
        status="Scheduled" if payload.mode == "scheduled" else "Planned",
        safety_status="Isolated",
        safety_notes="Simulation restricted to lab-only telemetry and internal SOC workflows.",
        expected_detection=payload.expected_detection or library_entry["expected_detection"],
        scenario_config={
            "mode": payload.mode,
            "intensity_level": payload.intensity_level,
            "duration_minutes": payload.duration_minutes,
            "training_mode": payload.training_mode,
            "safe_environment": True,
        },
        timeline=[],
        detection_summary={
            "expected_detection": payload.expected_detection or library_entry["expected_detection"],
            "status": "awaiting-execution",
        },
    )
    db.add(simulation)
    db.commit()
    db.refresh(simulation)
    return simulation


def execute_simulation(db: Session, *, simulation: RedTeamSimulation, actor_user_id: str) -> RedTeamSimulation:
    """
    Execute a recorded simulation and push its events through the SOC pipeline.

    The resulting telemetry is synthetic, but every downstream step is real:
    AI scoring, alert generation, threat-intel matching, correlation, incident
    creation, and playbook selection all happen through the normal platform.
    """
    payload = SimulationCreate(
        scenario_name=simulation.scenario_name,
        scenario_type=simulation.scenario_type,
        mode=simulation.mode,  # type: ignore[arg-type]
        target_user=simulation.target_user,
        target_device=simulation.target_device,
        intensity_level=simulation.intensity_level,  # type: ignore[arg-type]
        duration_minutes=simulation.duration_minutes,
        training_mode=simulation.training_mode,
        scheduled_for=simulation.scheduled_for,
        expected_detection=simulation.expected_detection,
    )
    events = _build_scenario_events(payload)
    simulation.status = "Running"
    simulation.started_at = _now()
    db.commit()

    timeline: list[dict] = []
    alerts_created: list[str] = []
    finding_scores: list[int] = []
    intel_matches_total = 0

    for event_payload in events:
        event = SecurityEvent(
            tenant_id=simulation.tenant_id,
            user_id=actor_user_id,
            event_type=str(event_payload["event_type"]),
            severity=str(event_payload.get("severity", "Medium")),
            source="attack-simulation-engine",
            event_payload={**event_payload, "simulation_id": simulation.id, "safe_lab": True, "training_mode": simulation.training_mode},
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        ai_score = score_event(db, simulation.tenant_id, event)
        persist_ai_finding(db, simulation.tenant_id, event, ai_score)
        finding_scores.append(ai_score.risk_score)

        intel_matches = evaluate_threat_intel(db, simulation.tenant_id, event.event_payload)
        intel_matches_total += len(intel_matches)
        if intel_matches:
            title = f"Threat intelligence match during {simulation.scenario_type} simulation"
            db.add(
                Alert(
                    tenant_id=simulation.tenant_id,
                    event_id=event.id,
                    severity="High",
                    title=title,
                    status="Open",
                    source="threat-intelligence",
                )
            )
            db.commit()
            alerts_created.append(title)

        if event.event_type in {"failed_login", "user_role_change", "device_anomaly", "external_connection", "login"}:
            rule_title = f"Simulation detection: {simulation.scenario_name}"
            db.add(
                Alert(
                    tenant_id=simulation.tenant_id,
                    event_id=event.id,
                    severity=SCENARIO_LIBRARY[simulation.scenario_type]["severity"],
                    title=rule_title,
                    status="Open",
                    source="attack-simulation-engine",
                )
            )
            db.commit()
            alerts_created.append(rule_title)

        timeline.append(_simulation_to_timeline_entry(event.event_payload, event.id, ai_score.risk_score, alerts_created[-2:]))

    incident = create_incident_ticket(
        db,
        tenant_id=simulation.tenant_id,
        payload=IncidentCreate(
            title=f"Simulation Incident: {simulation.scenario_name}",
            description=f"Lab scenario {simulation.scenario_type} executed to validate detections and response workflow.",
            severity=SCENARIO_LIBRARY[simulation.scenario_type]["severity"],
            affected_asset=simulation.target_device or simulation.target_user or "lab-environment",
        ),
        owner_user_id=actor_user_id,
    )
    append_incident_activity(
        db,
        incident=incident,
        actor_user_id=actor_user_id,
        activity_type="simulation_validation",
        notes="Incident automatically created from Cyber Attack Simulation Lab execution.",
        status="Investigating",
        response_stage="Identification",
    )

    playbook = _find_playbook(db, simulation.tenant_id, SCENARIO_LIBRARY[simulation.scenario_type]["playbook_trigger"])
    executed_steps = execute_playbook(db, playbook) if playbook else []
    if executed_steps:
        append_incident_activity(
            db,
            incident=incident,
            actor_user_id=actor_user_id,
            activity_type="playbook_execution",
            notes=f"Simulation triggered response playbook steps: {', '.join(executed_steps)}",
            status="Investigating",
            response_stage="Containment",
        )

    correlation = correlate_recent_events(db, simulation.tenant_id)

    simulation.status = "Completed"
    simulation.completed_at = _now()
    simulation.timeline = timeline
    simulation.detection_summary = {
        "alerts_created": len(alerts_created),
        "alert_titles": alerts_created,
        "max_ai_risk_score": max(finding_scores) if finding_scores else 0,
        "intel_matches": intel_matches_total,
        "incident_id": incident.id,
        "playbook_steps": executed_steps,
        "correlated_incident": correlation.incident_id if correlation else None,
        "training_mode": simulation.training_mode,
    }
    db.commit()
    db.refresh(simulation)
    return simulation


def stop_simulation(db: Session, *, simulation: RedTeamSimulation) -> RedTeamSimulation:
    """
    Stop a simulation before execution or mark it terminated.

    The MVP does not run long-lived attack jobs. This control mainly exists so
    analysts can cancel scheduled runs and preserve an auditable reason why a
    lab exercise did not proceed.
    """
    simulation.status = "Stopped"
    simulation.completed_at = _now()
    simulation.detection_summary = {
        **(simulation.detection_summary or {}),
        "status": "stopped-by-analyst",
    }
    db.commit()
    db.refresh(simulation)
    return simulation
