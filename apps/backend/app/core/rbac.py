"""
SOC-CyBe Security Platform
Module: RBAC Policy Map

Purpose:
This module defines the baseline role-based access control model used by
SOC-CyBe. It maps human roles to the permissions that backend routes enforce.

Security Considerations:
- Least privilege matters in a SOC because analysts, responders, viewers, and
  administrators should not all have the same operational reach.
- Keeping the baseline map in one place makes it easier to audit permission
  changes and align them with governance policies.

Related Components:
- `app/api/deps.py` permission enforcement
- `app/services/auth_service.py` role and permission seeding
"""

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "Admin": {
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "alerts:read",
        "devices:read",
        "logs:read",
        "users:manage",
    },
    "SOC Analyst": {
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "alerts:read",
        "devices:read",
        "logs:read",
    },
    "Incident Responder": {
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "alerts:read",
        "devices:read",
    },
    "Viewer": {
        "dashboard:read",
        "incidents:read",
        "alerts:read",
        "devices:read",
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check whether a role includes a specific named permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())
