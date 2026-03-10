"""
SOC-CyBe Security Platform
Module: Compliance Service

Purpose:
This module implements the parts of the platform that support privacy and
regulatory review: consent tracking, retention policy seeding, and compliance
report generation.

Security Considerations:
- Auditability depends on durable evidence, not runtime-only flags.
- Retention policy metadata is stored so operators can explain how long
  regulated data is kept and why.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.entities import ConsentRecord, LogEntry, RetentionPolicy, User
from app.schemas.compliance import ComplianceReportResponse


DEFAULT_RETENTION_POLICIES = [
    ("audit_logs", 365, "Security monitoring and regulatory review", "Archive then purge"),
    ("security_events", 365, "Threat detection and incident investigation", "Archive then purge"),
    ("sessions", 90, "Account security and anomaly review", "Purge expired sessions"),
    ("incidents", 730, "Incident response evidence retention", "Archive immutable records"),
    ("consent_records", 1095, "Privacy law accountability", "Retain for regulatory evidence"),
]


def seed_retention_policies(db: Session) -> None:
    """Ensure the platform has a baseline set of retention policies."""
    existing = {row.data_domain for row in db.scalars(select(RetentionPolicy)).all()}
    for data_domain, retention_days, legal_basis, purge_strategy in DEFAULT_RETENTION_POLICIES:
        if data_domain in existing:
            continue
        db.add(
            RetentionPolicy(
                data_domain=data_domain,
                retention_days=retention_days,
                legal_basis=legal_basis,
                purge_strategy=purge_strategy,
            )
        )
    db.commit()


def record_consent(
    db: Session,
    *,
    user: User,
    consent_type: str,
    consent_granted: bool,
    policy_version: str,
) -> ConsentRecord:
    """
    Store a consent decision and reflect it on the user record.

    Recording consent as its own entity is important for GDPR, POPIA, and other
    frameworks because an auditor may need to inspect historical evidence.
    """
    record = ConsentRecord(
        tenant_id=user.tenant_id,
        user_id=user.id,
        consent_type=consent_type,
        consent_granted=consent_granted,
        policy_version=policy_version,
    )
    user.consent_logged = consent_granted
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def build_compliance_report(db: Session, tenant_id: str | None) -> ComplianceReportResponse:
    """Build a high-level compliance snapshot for a tenant."""
    generated_at = datetime.now(timezone.utc)
    last_30_days = generated_at - timedelta(days=30)
    total_audit_logs = db.scalar(select(func.count()).select_from(LogEntry).where(LogEntry.tenant_id == tenant_id)) or 0
    recent_audit_logs = db.scalar(select(func.count()).select_from(LogEntry).where(LogEntry.tenant_id == tenant_id, LogEntry.timestamp >= last_30_days)) or 0
    consent_records = db.scalar(select(func.count()).select_from(ConsentRecord).where(ConsentRecord.tenant_id == tenant_id)) or 0
    retention_policies = db.scalar(select(func.count()).select_from(RetentionPolicy)) or 0
    return ComplianceReportResponse(
        generated_at=generated_at,
        frameworks=["GDPR", "POPIA", "CCPA", "ISO/IEC 27001", "NIST CSF", "OWASP ASVS"],
        total_audit_logs=total_audit_logs,
        audit_logs_last_30_days=recent_audit_logs,
        consent_records=consent_records,
        active_retention_policies=retention_policies,
        data_deletion_ready=True,
        encryption_controls=[
            "AES-256 application-layer encryption",
            "TLS-enforced transport controls",
            "Argon2/bcrypt password hashing",
        ],
    )
