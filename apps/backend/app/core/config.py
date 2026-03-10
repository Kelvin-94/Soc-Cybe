"""
SOC-CyBe Security Platform
Module: Configuration Loader

Purpose:
This module centralizes runtime configuration for the SOC-CyBe backend.
It loads environment variables, supports secret-file based deployments,
and exposes strongly typed settings to the rest of the application.

Security Considerations:
- Secrets can be read from mounted files so production deployments do not need
  to keep cryptographic material in plaintext environment variables.
- The data encryption key is validated to ensure it is suitable for AES-256 use.
- TLS and retention-related settings live here because they influence
  request trust and compliance posture across the whole platform.

Related Components:
- `app/core/security.py` for JWT signing and field encryption
- `app/db/session.py` for secure database connections
- `app/main.py` for startup behavior
"""

from functools import lru_cache
from pathlib import Path
import base64

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path_value: str | None) -> str | None:
    """
    Read a secret from disk when the deployment provides file-backed secrets.

    This is common in Docker Swarm, Kubernetes, and other orchestrators where
    keeping secrets out of plain environment variables is preferred.
    """
    if not path_value:
        return None
    path = Path(path_value)
    if not path.exists():
        raise ValueError(f"Secret file does not exist: {path}")
    return path.read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    """
    Strongly typed runtime settings for the SOC-CyBe backend.

    Keeping settings in one object makes it easier for developers and auditors
    to reason about which controls can be tuned by environment.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = Field(default="SOC-CyBe API", alias="APP_NAME")
    api_v1_prefix: str = Field(default="/api/v1", alias="API_V1_PREFIX")
    secret_key: str = Field(default="change-me-in-production", alias="SECRET_KEY")
    secret_key_file: str | None = Field(default=None, alias="SECRET_KEY_FILE")
    data_encryption_key: str | None = Field(default=None, alias="DATA_ENCRYPTION_KEY")
    data_encryption_key_file: str | None = Field(default=None, alias="DATA_ENCRYPTION_KEY_FILE")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    database_url: str = Field(
        default="postgresql+psycopg://soc_cybe:soc_cybe_password@localhost:5432/soc_cybe_db",
        alias="DATABASE_URL",
    )
    rate_limit_requests: int = Field(default=100, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")
    cors_origins: list[str] = Field(default=["http://localhost:3000"], alias="CORS_ORIGINS")
    bootstrap_admin_email: str = Field(default="admin@soc-cybe.io", alias="BOOTSTRAP_ADMIN_EMAIL")
    bootstrap_admin_password: str = Field(
        default="AdminZeroTrust!2026",
        alias="BOOTSTRAP_ADMIN_PASSWORD",
    )
    bootstrap_admin_password_file: str | None = Field(default=None, alias="BOOTSTRAP_ADMIN_PASSWORD_FILE")
    require_tls: bool = Field(default=True, alias="REQUIRE_TLS")
    strict_transport_security_seconds: int = Field(default=31536000, alias="STRICT_TRANSPORT_SECURITY_SECONDS")

    @property
    def effective_secret_key(self) -> str:
        """Return the JWT signing key, preferring a mounted secret file when available."""
        return _read_secret_file(self.secret_key_file) or self.secret_key

    @property
    def effective_bootstrap_admin_password(self) -> str:
        """Return the bootstrap credential from a secret file or fallback setting."""
        return _read_secret_file(self.bootstrap_admin_password_file) or self.bootstrap_admin_password

    @property
    def effective_data_encryption_key(self) -> bytes:
        """
        Return the AES-256 key used for application-layer field encryption.

        The system prefers an explicit base64url-encoded 32-byte key. A fallback
        is generated from the signing secret to keep local development usable,
        but production deployments should always provide a dedicated key.
        """
        raw_key = _read_secret_file(self.data_encryption_key_file) or self.data_encryption_key
        if raw_key:
            decoded = base64.urlsafe_b64decode(raw_key.encode("utf-8"))
            if len(decoded) != 32:
                raise ValueError("DATA_ENCRYPTION_KEY must decode to 32 bytes for AES-256")
            return decoded
        fallback = self.effective_secret_key.encode("utf-8")
        padded = (fallback * ((32 // len(fallback)) + 1))[:32]
        return padded


@lru_cache
def get_settings() -> Settings:
    """Cache settings so all modules share a consistent view of the runtime config."""
    return Settings()


settings = get_settings()
