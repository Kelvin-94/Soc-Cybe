"""
SOC-CyBe Security Platform
Module: Encrypted Database Types

Purpose:
This module provides SQLAlchemy field types that transparently encrypt and
decrypt values when they move between Python and the database.

Security Considerations:
- Encryption is handled at the ORM boundary so developers do not need to
  remember to encrypt every individual write manually.
- Decryption only happens inside trusted application logic.

Related Components:
- `app/core/security.py` encryption helpers
- `app/models/entities.py` models that store sensitive operational data
"""

from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from app.core.security import decrypt_value, encrypt_value


class EncryptedString(TypeDecorator[str]):
    """Persist string values in encrypted form while keeping model usage ergonomic."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect):
        """Encrypt values before they are written to storage."""
        if value is None:
            return None
        return encrypt_value(value)

    def process_result_value(self, value: str | None, dialect):
        """Decrypt values after they are read back from storage."""
        if value is None:
            return None
        return decrypt_value(value)
