"""
SOC-CyBe Security Platform
Module: Authentication and Session Service

Purpose:
This service handles baseline identity workflows: seeding roles and tenants,
bootstrapping the first admin, authenticating users, and recording sessions.

Security Considerations:
- Password checks update risk state so repeated failures become visible.
- Sessions are recorded and later verified during Zero Trust request handling.
- Tenant and role seeding is centralized so access policy stays consistent.

Related Components:
- `app/api/routes.py` login and admin bootstrap endpoints
- `app/api/deps.py` session verification
- `app/services/threat_monitor.py` suspicious login detection
"""

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.models.entities import Device, Permission, RiskScore, Role, RolePermission, Session as UserSession, Tenant, User
from app.services.compliance import seed_retention_policies
from app.services.risk_engine import calculate_risk_score
from app.services.soc_operations import seed_soc_modules
from app.services.threat_monitor import evaluate_login_attempt


DEFAULT_ROLE_PERMISSIONS = {
    "Admin": [
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "alerts:read",
        "devices:read",
        "logs:read",
        "users:manage",
    ],
    "SOC Analyst": [
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "alerts:read",
        "devices:read",
        "logs:read",
    ],
    "Incident Responder": [
        "dashboard:read",
        "incidents:read",
        "incidents:write",
        "alerts:read",
        "devices:read",
    ],
    "Viewer": [
        "dashboard:read",
        "incidents:read",
        "alerts:read",
        "devices:read",
    ],
}


def seed_roles_and_permissions(db: Session) -> None:
    """
    Ensure baseline RBAC and retention metadata exist in a fresh environment.

    Seeding is idempotent so startup and administrative workflows can call it
    safely without duplicating records.
    """
    permission_descriptions = {
        "dashboard:read": "Read dashboard metrics",
        "incidents:read": "View incidents",
        "incidents:write": "Create and update incidents",
        "alerts:read": "View alerts",
        "devices:read": "View monitored devices",
        "logs:read": "View audit logs",
        "users:manage": "Manage users and roles",
    }
    existing_permissions = {
        permission.name: permission for permission in db.scalars(select(Permission)).all()
    }
    for name, description in permission_descriptions.items():
        if name not in existing_permissions:
            permission = Permission(name=name, description=description)
            db.add(permission)
            existing_permissions[name] = permission
    db.flush()

    existing_roles = {role.name: role for role in db.scalars(select(Role)).all()}
    for role_name, permission_names in DEFAULT_ROLE_PERMISSIONS.items():
        role = existing_roles.get(role_name)
        if not role:
            role = Role(name=role_name, description=f"{role_name} access profile")
            db.add(role)
            db.flush()
            existing_roles[role_name] = role
        current_permission_ids = {assignment.permission_id for assignment in role.permissions}
        for permission_name in permission_names:
            permission = existing_permissions[permission_name]
            if permission.id not in current_permission_ids:
                db.add(RolePermission(role_id=role.id, permission_id=permission.id))
    db.commit()
    seed_retention_policies(db)


def bootstrap_admin_if_needed(db: Session) -> User:
    """
    Create the first administrative tenant and user when the system is empty.

    This keeps local deployments usable while still following the same secure
    password hashing and role assignment path as normal users.
    """
    seed_roles_and_permissions(db)
    tenant = db.scalar(select(Tenant).where(Tenant.organization_id == "soc-cybe-default"))
    if not tenant:
        tenant = Tenant(organization_id="soc-cybe-default", name="SOC-CyBe Default Tenant")
        db.add(tenant)
        db.flush()
    seed_soc_modules(db, tenant.id)
    admin = db.scalar(select(User).where(User.email == settings.bootstrap_admin_email))
    if admin:
        return admin
    admin_role = db.scalar(select(Role).where(Role.name == "Admin"))
    assert admin_role is not None
    admin = User(
        tenant_id=tenant.id,
        email=settings.bootstrap_admin_email,
        password_hash=hash_password(settings.effective_bootstrap_admin_password),
        role_id=admin_role.id,
        consent_logged=True,
        is_active=True,
    )
    db.add(admin)
    db.flush()
    db.add(
        RiskScore(
            tenant_id=tenant.id,
            user_id=admin.id,
            score=12,
            failed_logins=0,
            ip_reputation=96,
            device_trust=95,
            privilege_changes=0,
        )
    )
    db.commit()
    db.refresh(admin)
    return admin


def get_user_with_access_profile(db: Session, email: str) -> User | None:
    """Load a user together with the role and risk context needed for login."""
    statement = (
        select(User)
        .options(
            joinedload(User.role).joinedload(Role.permissions).joinedload(RolePermission.permission),
            joinedload(User.risk_score),
        )
        .where(User.email == email, User.deleted_at.is_(None))
    )
    return db.scalar(statement)


def authenticate_user(
    db: Session,
    email: str,
    password: str,
    *,
    ip_address: str,
    device_id: str,
) -> User | None:
    """
    Authenticate a user and update risk state based on the outcome.

    Successful and failed attempts are both security-relevant, so this method
    cooperates with the threat monitoring service rather than treating login
    as a simple yes/no operation.
    """
    user = get_user_with_access_profile(db, email)
    if not user or not user.is_active:
        evaluate_login_attempt(
            db,
            user=user,
            email=email,
            ip_address=ip_address,
            device_id=device_id,
            succeeded=False,
        )
        return None
    if not verify_password(password, user.password_hash):
        if user.risk_score:
            user.risk_score.failed_logins += 1
            user.risk_score.score = calculate_risk_score(
                failed_logins=user.risk_score.failed_logins,
                ip_reputation=user.risk_score.ip_reputation,
                device_trust=user.risk_score.device_trust,
                privilege_changes=user.risk_score.privilege_changes,
            )
            db.commit()
        evaluate_login_attempt(
            db,
            user=user,
            email=email,
            ip_address=ip_address,
            device_id=device_id,
            succeeded=False,
        )
        return None
    if user.risk_score:
        user.risk_score.failed_logins = 0
        user.risk_score.score = calculate_risk_score(
            failed_logins=0,
            ip_reputation=user.risk_score.ip_reputation,
            device_trust=user.risk_score.device_trust,
            privilege_changes=user.risk_score.privilege_changes,
        )
        db.commit()
    evaluate_login_attempt(
        db,
        user=user,
        email=email,
        ip_address=ip_address,
        device_id=device_id,
        succeeded=True,
    )
    return user


def collect_permissions(user: User) -> list[str]:
    """Flatten a user's role assignments into a sorted permission list."""
    if not user.role:
        return []
    return sorted({assignment.permission.name for assignment in user.role.permissions})


def record_session(
    db: Session,
    *,
    user_id: str,
    jwt_id: str,
    device_id: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> UserSession:
    """
    Persist a tracked session so later requests can be validated against it.

    The session record ties the JWT to device and network context, which is a
    key part of the platform's Zero Trust design.
    """
    device = None
    if device_id:
        device = db.scalar(select(Device).where(Device.device_id == device_id))
        if not device:
            # Device tracking matters because new or unexpected endpoints are a
            # common sign of account abuse or credential theft.
            device = Device(
                tenant_id=db.scalar(select(User.tenant_id).where(User.id == user_id)),
                user_id=user_id,
                device_id=device_id,
                device_type="Unknown",
                ip_address=ip_address or "unknown",
                location="Unknown",
                login_history=[],
                risk_score=0,
            )
            db.add(device)
            db.flush()
        device.login_history = [*device.login_history, {"ip_address": ip_address, "at": datetime.utcnow().isoformat()}]
        device.ip_address = ip_address or device.ip_address
    session = UserSession(
        tenant_id=db.scalar(select(User.tenant_id).where(User.id == user_id)),
        user_id=user_id,
        jwt_id=jwt_id,
        device_id=device_id,
        ip_address=ip_address,
        user_agent=user_agent,
        status="verified",
        last_seen=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session
