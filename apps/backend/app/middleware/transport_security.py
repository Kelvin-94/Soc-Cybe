"""
SOC-CyBe Security Platform
Module: Transport Security Middleware

Purpose:
This middleware tracks whether requests arrived over a secure channel and adds
secure transport headers to responses.

Security Considerations:
- The backend is designed to run behind HTTPS or a trusted reverse proxy.
- HSTS and related headers reduce downgrade and content-misuse risks in browser
  contexts.

Related Components:
- `app/api/deps.py` where TLS requirements are enforced for authenticated calls
- deployment configuration for reverse proxies and ingress controllers
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.config import settings


class TransportSecurityMiddleware(BaseHTTPMiddleware):
    """Annotate request transport security and enforce secure response headers."""
    async def dispatch(self, request: Request, call_next):
        """
        Determine whether the request arrived over HTTPS and set security headers.

        The request state flag is later consulted by authenticated dependencies
        before they allow privileged API actions.
        """
        forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        request.state.transport_secure = forwarded_proto == "https"
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            f"max-age={settings.strict_transport_security_seconds}; includeSubDomains"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
