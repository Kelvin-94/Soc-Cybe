"""
SOC-CyBe Security Platform
Module: AI Detection Engine

Purpose:
This module adds anomaly detection to the event pipeline. It builds lightweight
behavior baselines from historical telemetry and uses an Isolation Forest when
available, with a heuristic fallback that keeps the MVP functional even if ML
dependencies are not installed.

Security Considerations:
- AI findings do not replace deterministic detections. They complement rules by
  surfacing unusual behavior that may not match known signatures.
- Findings are stored as first-class records because analysts need to inspect
  why a model considered an event unusual.
- Model confidence is bounded and translated into operational severity so the
  alert engine can respond consistently.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import mean

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import AIAnomalyFinding, Alert, RiskScore, SecurityEvent

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - runtime fallback for constrained environments
    np = None
    IsolationForest = None


MODEL_VERSION = "ai-detection-engine-0.1"
AI_MODEL_REGISTRY: dict[str, dict] = {}


@dataclass
class AIScore:
    anomaly_detected: bool
    anomaly_type: str
    confidence_score: int
    risk_score: int
    severity: str
    recommended_action: str
    details: dict


def _coerce_datetime(value: str | None) -> datetime:
    """Turn stored timestamps into timezone-aware datetimes for feature extraction."""
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _extract_features(event_payload: dict) -> list[float]:
    """
    Convert an event payload into a small numeric feature vector.

    The feature set is intentionally explainable: event time, count-like fields,
    identity hints, and request/device context. Explainability matters in SOC
    systems because analysts need to justify why a model raised suspicion.
    """
    event_time = _coerce_datetime(event_payload.get("timestamp"))
    event_type = str(event_payload.get("event_type", "unknown"))
    source_type = str(event_payload.get("source_type", "unknown"))
    source_ip = str(event_payload.get("source_ip") or event_payload.get("ip_address") or "")
    username = str(event_payload.get("username") or "")
    device_id = str(event_payload.get("device_id") or "")
    count = float(event_payload.get("count", 1))

    return [
        float(event_time.hour),
        float(event_time.weekday()),
        count,
        float(len(source_ip)),
        float(len(username)),
        float(len(device_id)),
        float(sum(ord(char) for char in event_type) % 97),
        float(sum(ord(char) for char in source_type) % 89),
    ]


def _severity_from_risk(risk_score: int) -> str:
    """Translate a numeric AI risk score into the severity language used by the SOC."""
    if risk_score >= 85:
        return "Critical"
    if risk_score >= 65:
        return "High"
    if risk_score >= 40:
        return "Moderate"
    return "Low"


def train_models(db: Session, tenant_id: str | None, lookback_hours: int) -> tuple[bool, int, str]:
    """
    Train or refresh the AI model state for a tenant using historical events.

    The training data comes from stored security events, which lets the system
    improve over time as the environment generates more telemetry.
    """
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    rows = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id, SecurityEvent.created_at >= since)
        .order_by(SecurityEvent.created_at.desc())
        .limit(500)
    ).all()
    features = [_extract_features(row.event_payload or {}) for row in rows]
    baselines: dict[str, dict[str, float]] = defaultdict(dict)

    if rows:
        login_hours = [
            _coerce_datetime((row.event_payload or {}).get("timestamp")).hour
            for row in rows
            if (row.event_payload or {}).get("event_type") in {"login", "user_login_activity", "suspicious_login_detected"}
        ]
        api_counts = [float((row.event_payload or {}).get("count", 1)) for row in rows if "api" in str((row.event_payload or {}).get("event_type", "")).lower()]
        baselines["tenant"]["typical_login_hour"] = mean(login_hours) if login_hours else 9.0
        baselines["tenant"]["typical_api_count"] = mean(api_counts) if api_counts else 5.0

    model = None
    if IsolationForest is not None and np is not None and len(features) >= 8:
        model = IsolationForest(contamination=0.15, random_state=42)
        model.fit(np.array(features))

    AI_MODEL_REGISTRY[tenant_id or "default"] = {
        "model": model,
        "features": features,
        "baselines": baselines,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    return True, len(features), MODEL_VERSION


def _heuristic_score(event_payload: dict, baselines: dict[str, dict[str, float]]) -> AIScore:
    """Fallback anomaly scoring used when the statistical model is unavailable."""
    event_type = str(event_payload.get("event_type", "unknown"))
    count = int(event_payload.get("count", 1))
    hour = _coerce_datetime(event_payload.get("timestamp")).hour
    typical_hour = baselines.get("tenant", {}).get("typical_login_hour", 9.0)
    typical_api_count = baselines.get("tenant", {}).get("typical_api_count", 5.0)

    anomaly_points = 0
    anomaly_type = "behavioral-deviation"
    if "login" in event_type and abs(hour - typical_hour) >= 8:
        anomaly_points += 30
        anomaly_type = "unusual-login-pattern"
    if "api" in event_type.lower() and count > typical_api_count * 3:
        anomaly_points += 35
        anomaly_type = "abnormal-api-behavior"
    if "privilege" in event_type.lower():
        anomaly_points += 28
        anomaly_type = "privilege-escalation-anomaly"
    if "device" in event_type.lower():
        anomaly_points += 20
        anomaly_type = "anomalous-device-activity"
    if "data" in event_type.lower() or "database" in event_type.lower():
        anomaly_points += 25
        anomaly_type = "suspicious-data-access"

    confidence = max(15, min(95, anomaly_points + 20))
    risk_score = max(0, min(100, anomaly_points + 25))
    severity = _severity_from_risk(risk_score)
    return AIScore(
        anomaly_detected=risk_score >= 45,
        anomaly_type=anomaly_type,
        confidence_score=confidence,
        risk_score=risk_score,
        severity=severity,
        recommended_action="Review event context, compare with baseline, and escalate if correlated with other detections.",
        details={"mode": "heuristic", "anomaly_points": anomaly_points},
    )


def score_event(db: Session, tenant_id: str | None, event: SecurityEvent) -> AIScore:
    """
    Score a single event for anomalous behavior and return an explainable result.

    The engine prefers a trained Isolation Forest when enough historical data is
    available. If not, it falls back to a transparent heuristic model so the
    feature still works in small datasets.
    """
    registry_key = tenant_id or "default"
    state = AI_MODEL_REGISTRY.get(registry_key)
    if not state:
        train_models(db, tenant_id, lookback_hours=168)
        state = AI_MODEL_REGISTRY.get(registry_key, {"model": None, "baselines": {}})

    payload = event.event_payload or {}
    baselines = state.get("baselines", {})
    model = state.get("model")
    features = _extract_features(payload)

    if model is None or np is None:
        return _heuristic_score(payload, baselines)

    prediction = int(model.predict(np.array([features]))[0])
    raw_score = float(model.decision_function(np.array([features]))[0])
    anomaly_detected = prediction == -1
    confidence = max(10, min(98, int((1 - raw_score) * 100)))
    event_type = str(payload.get("event_type", "unknown")).lower()

    anomaly_type = "behavioral-anomaly"
    if "login" in event_type:
        anomaly_type = "unusual-login-pattern"
    elif "api" in event_type:
        anomaly_type = "abnormal-api-behavior"
    elif "privilege" in event_type:
        anomaly_type = "privilege-escalation-anomaly"
    elif "device" in event_type:
        anomaly_type = "anomalous-device-activity"
    elif "data" in event_type or "database" in event_type:
        anomaly_type = "suspicious-data-access"

    risk_score = max(0, min(100, confidence + (10 if anomaly_detected else -10)))
    severity = _severity_from_risk(risk_score)
    return AIScore(
        anomaly_detected=anomaly_detected,
        anomaly_type=anomaly_type,
        confidence_score=confidence,
        risk_score=risk_score,
        severity=severity,
        recommended_action="Validate against user baseline, threat intelligence, and correlated events before containment.",
        details={"mode": "isolation-forest", "decision_score": raw_score},
    )


def persist_ai_finding(db: Session, tenant_id: str | None, event: SecurityEvent, score: AIScore) -> AIAnomalyFinding:
    """
    Persist an AI anomaly finding and create an alert when the anomaly is meaningful.

    Storing findings separately lets the platform show AI-specific detections
    without mixing them into generic event storage.
    """
    payload = event.event_payload or {}
    finding = AIAnomalyFinding(
        tenant_id=tenant_id,
        user_id=event.user_id,
        device_id=payload.get("device_id"),
        event_id=event.id,
        anomaly_type=score.anomaly_type,
        confidence_score=score.confidence_score,
        risk_score=score.risk_score,
        recommended_action=score.recommended_action,
        severity=score.severity,
        details=score.details,
    )
    db.add(finding)

    if score.anomaly_detected:
        db.add(
            Alert(
                tenant_id=tenant_id,
                event_id=event.id,
                severity="High" if score.severity in {"High", "Critical"} else "Medium",
                title=f"AI anomaly detected: {score.anomaly_type}",
                status="Open",
                source="ai-detection-engine",
            )
        )

    if event.user_id:
        risk = db.scalar(select(RiskScore).where(RiskScore.user_id == event.user_id))
        if risk:
            # AI risk is folded into the stored score, but we keep the higher of
            # the two so deterministic detections still matter.
            risk.score = max(risk.score, score.risk_score)
    db.commit()
    db.refresh(finding)
    return finding
