"""
SOC-CyBe Security Platform
Module: Security Monitoring Middleware

Purpose:
This middleware inspects every request before route handling and records
anomaly signals that may indicate probing, injection attempts, or malformed
traffic.

Security Considerations:
- Capturing suspicious traffic early gives analysts visibility even when the
  request never reaches an authenticated route.
- The middleware stores anomaly flags on `request.state` so deeper Zero Trust
  logic can make use of the same signal later in the request.

Related Components:
- `app/services/zero_trust.py` for anomaly detection helpers
- `app/api/deps.py` for authenticated request risk decisions
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.db.session import SessionLocal
from app.services.zero_trust import detect_request_anomalies, log_security_event


class SecurityMonitoringMiddleware(BaseHTTPMiddleware):
    """Inspect inbound requests for suspicious request-shape indicators."""
    async def dispatch(self, request: Request, call_next):
        """
        Flag suspicious requests, persist an event when necessary, and forward.

        The middleware intentionally does not block traffic on its own. Instead,
        it gives the Zero Trust layer and analysts more context to act on.
        """
        user_agent = request.headers.get("user-agent")
        anomaly_flags = detect_request_anomalies(request.url.path, request.url.query, user_agent)
        request.state.anomaly_flags = anomaly_flags

        if anomaly_flags:
            with SessionLocal() as db:
                # Record anonymous anomaly context early so the SOC has evidence
                # even if the request fails authentication later.
                log_security_event(
                    db,
                    tenant_id=None,
                    user_id=None,
                    event_type="request_anomaly_detected",
                    severity="Medium" if len(anomaly_flags) == 1 else "High",
                    source="security-monitor-middleware",
                    event_payload={
                        "path": request.url.path,
                        "query": request.url.query,
                        "flags": anomaly_flags,
                    },
                )
                db.commit()

        response = await call_next(request)
        # These headers are useful in testing and operational debugging because
        # they confirm that the gateway path evaluated the request.
        response.headers["X-Zero-Trust-Checked"] = "true"
        if anomaly_flags:
            response.headers["X-Anomaly-Flags"] = str(len(anomaly_flags))
        return response
