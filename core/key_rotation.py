"""AgentShield V3 — Cryptographic Key Management & Rotation Interface.

Supports:
- Key lifecycle states: ACTIVE (can sign & verify), RETIRED (historical verify only), REVOKED (rejected).
- Planned key rotation without invalidating historical receipts.
- Cryptographic verifier registry supporting key IDs (kid).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union

from .crypto import (
    PrivateKeyType,
    PublicKeyType,
    generate_keypair,
    public_key_to_b64,
    sign,
    verify,
)


class KeyState(str, Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


@dataclass
class KeyMetadata:
    kid: str
    public_key: str
    private_key: Optional[str] = None
    state: KeyState = KeyState.ACTIVE
    created_at: float = field(default_factory=time.time)
    retired_at: Optional[float] = None
    revoked_at: Optional[float] = None

    def is_sign_permitted(self) -> bool:
        return self.state == KeyState.ACTIVE and self.private_key is not None

    def is_verify_permitted(self, allow_retired: bool = True) -> bool:
        if self.state == KeyState.REVOKED:
            return False
        if self.state == KeyState.RETIRED:
            return allow_retired
        return self.state == KeyState.ACTIVE


class KeyRotationManager:
    """Manages active, retired, and revoked signing and verification keys."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyMetadata] = {}
        self._active_kid: Optional[str] = None

    def register_key(
        self,
        kid: str,
        public_key: str,
        private_key: Optional[str] = None,
        state: KeyState = KeyState.ACTIVE,
    ) -> KeyMetadata:
        meta = KeyMetadata(
            kid=kid,
            public_key=public_key,
            private_key=private_key,
            state=state,
        )
        self._keys[kid] = meta
        if state == KeyState.ACTIVE and self._active_kid is None:
            self._active_kid = kid
        return meta

    def generate_and_add_active_key(self, kid: str) -> KeyMetadata:
        priv_b64, pub_b64 = generate_keypair()
        return self.register_key(kid=kid, public_key=pub_b64, private_key=priv_b64, state=KeyState.ACTIVE)

    def rotate_active_key(self, new_kid: str) -> KeyMetadata:
        """Retire the current active key and generate a fresh active key."""
        if self._active_kid and self._active_kid in self._keys:
            old_meta = self._keys[self._active_kid]
            old_meta.state = KeyState.RETIRED
            old_meta.retired_at = time.time()

        new_meta = self.generate_and_add_active_key(new_kid)
        self._active_kid = new_kid
        return new_meta

    def revoke_key(self, kid: str) -> None:
        """Revoke a compromised key. Revoked keys are rejected for all operations."""
        if kid in self._keys:
            self._keys[kid].state = KeyState.REVOKED
            self._keys[kid].revoked_at = time.time()
            if self._active_kid == kid:
                self._active_kid = None

    def get_active_signing_key(self) -> KeyMetadata:
        if not self._active_kid or self._active_kid not in self._keys:
            raise RuntimeError("No active signing key available in manager")
        meta = self._keys[self._active_kid]
        if not meta.is_sign_permitted():
            raise RuntimeError(f"Key {self._active_kid} is not permitted for signing")
        return meta

    def get_key(self, kid: str) -> Optional[KeyMetadata]:
        return self._keys.get(kid)

    def verify_with_kid(
        self,
        kid: str,
        signature: str,
        message: Union[str, bytes],
        allow_retired: bool = True,
    ) -> bool:
        """Verify signature using public key identified by kid, obeying rotation rules."""
        meta = self.get_key(kid)
        if not meta:
            return False
        if not meta.is_verify_permitted(allow_retired=allow_retired):
            return False
        return verify(signature, message, meta.public_key)
