"""
SOC-CyBe Security Platform
Module: Backend Package

Purpose:
This package contains the FastAPI backend for SOC-CyBe. The backend is
responsible for authentication, Zero Trust request enforcement, event
processing, detection workflows, compliance reporting, and operational APIs.

Security Considerations:
- Backend modules are expected to validate every request before trust is granted.
- Sensitive data is protected with encryption and careful schema design.
- Logging and monitoring are first-class concerns because this platform is itself
  a security system that must withstand review and audit.

Related Components:
- `app/main.py` application bootstrap
- `app/api` REST API surface
- `app/services` detection, response, and compliance workflows
"""
