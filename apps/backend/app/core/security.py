"""
SOC-CyBe Security Platform
Module: Security Primitives

Purpose:
This module contains the core cryptographic helpers used by the backend.
It handles password hashing, JWT creation and verification, and
application-layer field encryption for sensitive values stored in the database.

Security Considerations:
- Passwords are hashed with Argon2 or bcrypt and are never persisted in plaintext.
- JWTs are signed with a configured key so API clients can be authenticated.
- AES-GCM is used for authenticated encryption of sensitive fields such as
  IP addresses and user agent data; this protects data at rest and provides
  tamper detection for encrypted values.

Related Components:
- `app/core/config.py` for secret material and encryption keys
- `app/db/types.py` for encrypted SQLAlchemy field types
- `app/api/deps.py` for token validation during request processing
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def get_aesgcm() -> AESGCM:
    """
    Build the AES-GCM cipher used for field-level encryption.

    AES-GCM is chosen because it provides confidentiality and integrity in a
    single primitive, which is useful for audit-sensitive stored values.
    """
    return AESGCM(settings.effective_data_encryption_key)


def encrypt_value(value: str) -> str:
    """
    Encrypt a plaintext string for storage in the database.

    A fresh nonce is generated for every encryption operation to prevent
    repeated plaintext values from producing the same ciphertext.
    """
    nonce = uuid4().bytes[:12]
    ciphertext = get_aesgcm().encrypt(nonce, value.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_value(value: str) -> str:
    """Decrypt an encrypted field value back into plaintext for application use."""
    decoded = base64.urlsafe_b64decode(value.encode("utf-8"))
    nonce = decoded[:12]
    ciphertext = decoded[12:]
    plaintext = get_aesgcm().decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def hash_password(password: str) -> str:
    """
    Hash a user password using the configured password context.

    This is part of SOC-CyBe's secure authentication architecture and prevents
    credential theft from exposing usable passwords if the database is leaked.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compare a supplied password to its stored hash without exposing the hash logic to callers."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    subject: str,
    role: str,
    expires_minutes: int | None = None,
    extra_claims: dict | None = None,
) -> str:
    """
    Create a signed JWT for an authenticated SOC-CyBe session.

    The token carries the subject, role, expiry, and a unique JWT ID (`jti`).
    The `jti` matters because the Zero Trust request path checks every token
    against a tracked session record rather than trusting the token alone.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    payload = {"sub": subject, "role": role, "exp": expire, "jti": uuid4().hex}
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.effective_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """
    Verify and decode a JWT presented to the API.

    Invalid tokens raise an error so callers can deny access early in the
    request pipeline before sensitive logic is executed.
    """
    try:
        return jwt.decode(token, settings.effective_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError("Invalid token") from exc
