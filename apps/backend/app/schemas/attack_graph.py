"""
SOC-CyBe Security Platform
Module: Attack Graph Schemas

Purpose:
These models define the API shape for the real-time visual attack graph used
by analysts to understand attacker movement, lateral activity, and incident
scope.

Security Notes:
- The graph exposes investigation context, not raw unrestricted database
  access. Every node and edge is derived from tenant-scoped security evidence.
- Risk and threat-intelligence markers are included so analysts can prioritize
  response quickly without reading every underlying log first.
"""

from datetime import datetime
from pydantic import BaseModel


class AttackGraphNode(BaseModel):
    """Entity node shown in the investigation graph."""
    id: str
    node_type: str
    label: str
    risk_score: int
    risk_level: str
    color: str
    intel_match: bool
    alert_count: int
    details: dict


class AttackGraphEdge(BaseModel):
    """Relationship edge connecting two entities in the graph."""
    id: str
    source: str
    target: str
    action: str
    timestamp: datetime
    source_system: str
    destination_system: str
    severity: str
    details: dict


class AttackGraphTimelineItem(BaseModel):
    """Step-by-step timeline entry for replaying an attack story."""
    timestamp: datetime
    event_id: str
    action: str
    actor: str | None
    target: str | None
    severity: str
    description: str


class AttackGraphResponse(BaseModel):
    """Complete attack-graph projection returned to the frontend."""
    incident_id: str | None
    active_attack_paths: int
    compromised_devices: int
    high_risk_users: int
    ongoing_incidents: int
    ai_attack_path_suggestions: list[str]
    lateral_movement_paths: list[list[str]]
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]
    timeline: list[AttackGraphTimelineItem]
