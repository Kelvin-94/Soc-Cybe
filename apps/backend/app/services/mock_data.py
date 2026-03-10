"""
SOC-CyBe Security Platform
Module: Dashboard Mock Data

Purpose:
This module provides static fallback data for early frontend development and
demo-friendly dashboard rendering when persistent data is not yet available.

Developer Note:
As more frontend views are wired to live APIs, this module should continue to
shrink. It exists to keep the UI usable during incremental backend work.
"""

from datetime import datetime, timedelta, timezone

from app.core.rbac import ROLE_PERMISSIONS
from app.services.risk_engine import calculate_risk_score


NOW = datetime.now(timezone.utc)

USERS = {
    "admin@soc-cybe.io": {
        "id": "usr_admin_001",
        "email": "admin@soc-cybe.io",
        "password": "AdminZeroTrust!2026",
        "role": "Admin",
        "failed_logins": 1,
        "ip_reputation": 92,
        "device_trust": 90,
        "privilege_changes": 1,
    },
    "analyst@soc-cybe.io": {
        "id": "usr_analyst_002",
        "email": "analyst@soc-cybe.io",
        "password": "AnalystZeroTrust!2026",
        "role": "SOC Analyst",
        "failed_logins": 3,
        "ip_reputation": 80,
        "device_trust": 73,
        "privilege_changes": 0,
    },
}

ALERTS = [
    {
        "id": "alt-401",
        "severity": "Critical",
        "title": "Credential stuffing burst detected",
        "source": "Auth Gateway",
        "timestamp": NOW - timedelta(minutes=3),
        "status": "Investigating",
    },
    {
        "id": "alt-402",
        "severity": "High",
        "title": "Privilege escalation attempt on finance API",
        "source": "API Shield",
        "timestamp": NOW - timedelta(minutes=10),
        "status": "Escalated",
    },
    {
        "id": "alt-403",
        "severity": "Medium",
        "title": "Anomalous login from new geography",
        "source": "Identity Monitor",
        "timestamp": NOW - timedelta(minutes=18),
        "status": "Queued",
    },
]

INCIDENTS = [
    {
        "id": "inc-2201",
        "title": "Compromised API token investigation",
        "severity": "Critical",
        "owner": "M. Dlamini",
        "status": "Active",
        "response_stage": "Containment",
    },
    {
        "id": "inc-2202",
        "title": "Endpoint malware triage",
        "severity": "High",
        "owner": "N. Patel",
        "status": "Active",
        "response_stage": "Eradication",
    },
]

DEVICES = [
    {
        "device_id": "dev-001",
        "device_type": "Workstation",
        "ip_address": "10.42.1.24",
        "location": "Johannesburg",
        "risk_score": 31,
        "status": "Trusted",
    },
    {
        "device_id": "dev-002",
        "device_type": "Mobile",
        "ip_address": "172.16.2.11",
        "location": "Frankfurt",
        "risk_score": 66,
        "status": "Challenged",
    },
]

AUDIT_LOGS = []
SESSIONS = [
    {
        "session_id": "ses-1001",
        "user_id": "usr_admin_001",
        "ip_address": "10.42.1.24",
        "device_id": "dev-001",
        "status": "verified",
        "last_seen": NOW - timedelta(minutes=1),
    },
    {
        "session_id": "ses-1002",
        "user_id": "usr_analyst_002",
        "ip_address": "172.16.2.11",
        "device_id": "dev-002",
        "status": "step-up-authentication",
        "last_seen": NOW - timedelta(minutes=4),
    },
]


def get_user(email: str) -> dict | None:
    """Return a demo user profile for the fallback dashboard/auth stubs."""
    user = USERS.get(email)
    if not user:
        return None
    risk_score = calculate_risk_score(
        failed_logins=user["failed_logins"],
        ip_reputation=user["ip_reputation"],
        device_trust=user["device_trust"],
        privilege_changes=user["privilege_changes"],
    )
    return {
        "user_id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "risk_score": risk_score,
        "device_trust": user["device_trust"],
        "permissions": sorted(ROLE_PERMISSIONS[user["role"]]),
        "password": user["password"],
    }


def build_dashboard() -> dict:
    """Construct a fallback dashboard payload when live data is unavailable."""
    return {
        "metrics": [
            {"label": "Threats blocked", "value": 842, "change": 14.2},
            {"label": "Suspicious logins", "value": 19, "change": 8.1},
            {"label": "API abuse attempts", "value": 63, "change": 5.4},
            {"label": "Devices at risk", "value": 7, "change": -2.8},
        ],
        "alerts": ALERTS,
        "incidents": INCIDENTS,
        "devices": DEVICES,
    }
