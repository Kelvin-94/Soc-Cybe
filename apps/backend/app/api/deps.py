"""
SOC-CyBe Security Platform
Module: API Dependencies and Request Guards

Purpose:
This module holds FastAPI dependencies that authenticate callers, apply
rate limits, enforce permissions, and emit audit records.

Security Considerations:
- Every protected request is verified against both the JWT and the stored session.
- Audit entries are created for allowed actions so analysts can reconstruct
  who touched which route and when.
- Permission enforcement happens after identity verification so the platform
  can distinguish authentication failures from authorization failures.
"""

from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.rate_limit import InMemoryRateLimiter
from app.core.security import decode_token
from app.db.session import get_db
from app.models.entities import LogEntry, RiskScore, Role, RolePermission, Session as UserSession, User
from app.schemas.security import AuditLogEntry, AuthenticatedUser
from app.services.mock_data import AUDIT_LOGS
from app.services.threat_monitor import record_behavioral_alert
from app.services.zero_trust import assess_zero_trust_access, log_security_event, update_risk_from_request


bearer_scheme = HTTPBearer(auto_error=True)
rate_limiter = InMemoryRateLimiter(
    limit=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)


def append_audit_log(
    *,
    db: Session | None,
    tenant_id: str | None,
    user_id: str,
    ip_address: str,
    endpoint: str,
    action: str,
    status_text: str,
) -> None:
    """
    Record an audit event in memory and in persistent storage when available.

    SOC-CyBe keeps audit evidence because access traces are important for both
    incident investigations and regulatory review.
    """
    entry = AuditLogEntry(
        timestamp=datetime.now(timezone.utc),
        user_id=user_id,
        ip_address=ip_address,
        endpoint=endpoint,
        action=action,
        status=status_text,
    )
    AUDIT_LOGS.append(entry.model_dump())
    if db is not None:
        db.add(
            LogEntry(
                tenant_id=tenant_id,
                user_id=user_id,
                ip_address=ip_address,
                endpoint=endpoint,
                action=action,
                status=status_text,
                metadata_json={"immutable_view": True},
            )
        )
        db.commit()


def get_current_user(
    request: Request,
    x_forwarded_for: str | None = Header(default=None),
    user_agent: str | None = Header(default=None),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    """
    Authenticate and contextualize the current API caller.

    Process:
    1. Require a valid JWT
    2. Require a matching active session record
    3. Evaluate request risk and anomalies
    4. Record audit and security events
    5. Return a trusted user context for route handlers

    Security Notes:
    - This is the core of the platform's Zero Trust request model.
    - TLS is required for non-local authenticated traffic.
    - Session state is checked so a valid token alone is not enough.
    """
    client_host = request.client.host if request.client else "unknown"
    is_local_client = client_host in {"127.0.0.1", "::1", "localhost"}
    if settings.require_tls and not getattr(request.state, "transport_secure", False) and not is_local_client:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TLS is required")
    payload = decode_token(credentials.credentials)
    db_user = db.scalar(
        select(User)
        .options(
            joinedload(User.role).joinedload(Role.permissions).joinedload(RolePermission.permission),
            joinedload(User.risk_score),
            joinedload(User.sessions),
        )
        .where(User.id == payload["sub"], User.deleted_at.is_(None))
    )
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or missing user")
    jwt_id = payload.get("jti")
    session_record = db.scalar(select(UserSession).where(UserSession.jwt_id == jwt_id, UserSession.user_id == db_user.id))
    if not session_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown session")
    if session_record.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        session_record.status = "expired"
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    permissions = []
    if db_user.role:
        permissions = sorted({assignment.permission.name for assignment in db_user.role.permissions})
    client_ip = x_forwarded_for or (request.client.host if request.client else "unknown")
    request_risk, decision, factors, anomaly_flags = assess_zero_trust_access(
        risk_score=db_user.risk_score,
        session=session_record,
        request_path=str(request.url.path),
        request_query=request.url.query,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    middleware_flags = getattr(request.state, "anomaly_flags", [])
    if middleware_flags:
        anomaly_flags = sorted(set([*anomaly_flags, *middleware_flags]))
        factors["anomaly_flags"] = len(anomaly_flags)
    session_record.last_seen = datetime.utcnow()
    if decision == "deny":
        session_record.status = "blocked"
        if db_user.risk_score:
            db_user.risk_score.privilege_changes += 1
            update_risk_from_request(db_user.risk_score, request_risk)
        # Denials are recorded explicitly because they can indicate active abuse
        # or an account behaving outside its normal pattern.
        log_security_event(
            db,
            tenant_id=db_user.tenant_id,
            user_id=db_user.id,
            event_type="zero_trust_denial",
            severity="High",
            source="request-guard",
            event_payload={"path": str(request.url.path), "factors": factors, "anomalies": anomaly_flags},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Zero Trust policy denied request")
    if decision == "step-up-authentication":
        session_record.status = "step-up-authentication"
        # Step-up events are softer than denials but still important for analysts
        # because they often mark the beginning of suspicious behavior.
        log_security_event(
            db,
            tenant_id=db_user.tenant_id,
            user_id=db_user.id,
            event_type="step_up_required",
            severity="Medium",
            source="risk-engine",
            event_payload={"path": str(request.url.path), "factors": factors, "anomalies": anomaly_flags},
        )
    else:
        session_record.status = "verified"
    if anomaly_flags:
        # Behavioral alerts convert raw anomaly flags into analyst-facing signals.
        record_behavioral_alert(
            db,
            tenant_id=db_user.tenant_id,
            user_id=db_user.id,
            source="behavior-monitor",
            title="Abnormal request behavior detected",
            anomaly_flags=anomaly_flags,
            request_path=str(request.url.path),
            severity="Medium" if len(anomaly_flags) == 1 else "High",
        )
        log_security_event(
            db,
            tenant_id=db_user.tenant_id,
            user_id=db_user.id,
            event_type="request_anomaly_detected",
            severity="Medium" if len(anomaly_flags) == 1 else "High",
            source="anomaly-middleware",
            event_payload={"path": str(request.url.path), "flags": anomaly_flags},
        )
    update_risk_from_request(db_user.risk_score, request_risk)
    db.commit()
    user = AuthenticatedUser(
        user_id=payload["sub"],
        tenant_id=db_user.tenant_id,
        email=db_user.email,
        role=db_user.role.name if db_user.role else payload["role"],
        risk_score=getattr(db_user.risk_score, "score", payload.get("risk_score", 40)),
        device_trust=getattr(db_user.risk_score, "device_trust", payload.get("device_trust", 75)),
        permissions=permissions or payload.get("permissions", []),
        session_id=session_record.id,
        session_status=session_record.status,
        zero_trust_decision=decision,
        request_risk_score=request_risk,
    )
    subject = f"{user.user_id}:{client_ip}"
    rate_limiter.check(subject)
    append_audit_log(
        db=db,
        tenant_id=db_user.tenant_id,
        user_id=user.user_id,
        ip_address=client_ip,
        endpoint=str(request.url.path),
        action=f"{request.method} {request.url.path}",
        status_text="allowed",
    )
    return user


def require_permission(permission: str) -> Callable[[AuthenticatedUser], AuthenticatedUser]:
    """
    Build a dependency that enforces a named RBAC permission.

    Developer Note:
    Use named permissions rather than ad hoc role checks in route handlers. This
    keeps authorization policy explicit and easier to audit.
    """
    def checker(
        request: Request,
        user: AuthenticatedUser = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> AuthenticatedUser:
        """Reject callers that do not hold the required permission."""
        if permission not in user.permissions:
            log_security_event(
                db,
                tenant_id=user.tenant_id,
                user_id=user.user_id,
                event_type="authorization_failure",
                severity="High",
                source="rbac-policy",
                event_payload={"path": str(request.url.path), "permission": permission, "role": user.role},
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}",
            )
        if permission in {"users:manage", "incidents:write"} and user.request_risk_score >= 70:
            if user.role != "Admin" and permission == "users:manage":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Privilege escalation policy blocked this action",
                )
        return user

    return checker
