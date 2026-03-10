"""
SOC-CyBe Security Platform
Module: FastAPI Application Bootstrap

Purpose:
This is the backend entry point. It configures middleware, creates database
tables on startup for the local MVP, and registers the API router.

Security Considerations:
- Security middleware is installed before the router so transport and anomaly
  controls apply consistently.
- Startup seeding is limited to baseline security metadata needed to make the
  platform usable in a fresh environment.

Related Components:
- `app/api/routes.py` for endpoint definitions
- `app/middleware/*` for request protection
- `app/services/auth_service.py` for baseline security seeding
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import settings
from app.db.session import engine
from app.middleware.security_monitor import SecurityMonitoringMiddleware
from app.middleware.transport_security import TransportSecurityMiddleware
from app.models.base import Base
from app.services.auth_service import seed_roles_and_permissions
from sqlalchemy.orm import Session


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TransportSecurityMiddleware)
app.add_middleware(SecurityMonitoringMiddleware)

app.include_router(router, prefix=settings.api_v1_prefix)


@app.on_event("startup")
def startup() -> None:
    """
    Initialize local database structures and seed baseline SOC metadata.

    In a mature production deployment this would typically be handled by
    migrations, but for the MVP it keeps the environment self-contained.
    """
    Base.metadata.create_all(bind=engine)
    with Session(engine) as db:
        seed_roles_and_permissions(db)


@app.get("/health", tags=["system"])
def healthcheck() -> dict[str, str]:
    """Expose a minimal liveness endpoint for operators and automation."""
    return {"status": "ok", "service": settings.app_name}
