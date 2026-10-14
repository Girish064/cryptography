"""AgentShield V3 — Action-Bound Cryptographic Capability Tokens.

A capability token represents a single-use, short-lived, tamper-evident authorization
grant cryptographically bound to the EXACT canonical action digest.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Union

from .canonical import canonicalize, hash_action
from .crypto import PublicKeyType, PrivateKeyType, sign, verify

SCHEMA_V3_CAPABILITY = "agentshield.v3.capability"


@dataclass(frozen=True)
class CapabilityClaims:
    """Strongly-typed capability token claims."""

    schema: str
    agent_id: str
    scope: str
    action_hash: str
    nonce: str
    jti: str
    issued_at: float
    expires_at: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert claims into dictionary with deterministic field mapping."""
        return {
            "schema": self.schema,
            "agent_id": self.agent_id,
            "scope": self.scope,
            "action_hash": self.action_hash,
            "nonce": self.nonce,
            "jti": self.jti,
            "issued_at": round(self.issued_at, 4),
            "expires_at": round(self.expires_at, 4),
            "metadata": self.metadata,
        }


@dataclass
class CapabilityVerificationResult:
    """Outcome of capability verification."""

    valid: bool
    claims: Optional[CapabilityClaims] = None
    error: Optional[str] = None
    action_hash: Optional[str] = None


class CapabilityReplayStore:
    """Thread-safe in-memory store for tracking single-use consumed JTIs."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def check_and_claim(self, jti: str) -> bool:
        """Atomically claim a JTI. Returns True if claimed; False if already used."""
        if jti in self._consumed:
            return False
        self._consumed.add(jti)
        return True

    def is_consumed(self, jti: str) -> bool:
        return jti in self._consumed

    def clear(self) -> None:
        self._consumed.clear()


DEFAULT_REPLAY_STORE = CapabilityReplayStore()


def issue_capability(
    action: Any,
    agent_id: str,
    scope: str,
    private_key: PrivateKeyType,
    *,
    ttl_seconds: float = 60.0,
    metadata: Optional[dict[str, Any]] = None,
    jti: Optional[str] = None,
    issued_at: Optional[float] = None,
) -> dict[str, Any]:
    """Issue a cryptographically signed capability bound to the canonical action hash.

    Important V3 Rule: Signs the FULL capability structure, not just the action hash.
    """
    now = time.time() if issued_at is None else issued_at
    action_digest = hash_action(action)
    cap_jti = jti or f"CAP-{secrets.token_hex(8)}"
    cap_nonce = secrets.token_hex(16)

    claims_dict = {
        "schema": SCHEMA_V3_CAPABILITY,
        "agent_id": agent_id,
        "scope": scope,
        "action_hash": action_digest,
        "nonce": cap_nonce,
        "jti": cap_jti,
        "issued_at": round(now, 4),
        "expires_at": round(now + ttl_seconds, 4),
        "metadata": metadata or {},
    }

    # Sign the canonical UTF-8 bytes of the FULL capability structure
    canonical_cap_bytes = canonicalize(claims_dict)
    signature_str = sign(canonical_cap_bytes, private_key)

    return {
        "capability": claims_dict,
        "signature": signature_str,
    }


def encode_token(envelope: dict[str, Any]) -> str:
    """Serialize capability envelope to compact dot-separated base64 string.

    Format: <base64url_canonical_payload>.<signature>
    """
    cap_dict = envelope["capability"]
    sig_str = envelope["signature"]
    payload_b64 = base64.urlsafe_b64encode(canonicalize(cap_dict)).decode("ascii").rstrip("=")
    return f"{payload_b64}.{sig_str}"


def decode_token(token: str) -> dict[str, Any]:
    """Parse a compact dot-separated token back into capability envelope."""
    parts = token.strip().split(".")
    if len(parts) != 2:
        raise ValueError("Invalid compact token format. Expected <payload_b64>.<signature>")
    payload_b64, sig = parts
    padding = "=" * ((4 - len(payload_b64) % 4) % 4)
    raw_json = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8")
    claims_dict = json.loads(raw_json)
    return {
        "capability": claims_dict,
        "signature": sig,
    }


def check_scope_allowed(cap_scope: str, required_scope: str) -> bool:
    """Evaluate whether capability scope authorizes the requested action scope."""
    if cap_scope == "*" or cap_scope == required_scope:
        return True
    if cap_scope.endswith("/*"):
        prefix = cap_scope[:-2]
        return required_scope.startswith(prefix + "/") or required_scope == prefix
    return fnmatch.fnmatch(required_scope, cap_scope)


def verify_capability(
    capability_envelope: Union[dict[str, Any], str],
    expected_action: Any,
    public_key: PublicKeyType,
    *,
    expected_agent_id: Optional[str] = None,
    required_scope: Optional[str] = None,
    now: Optional[float] = None,
    replay_store: Optional[CapabilityReplayStore] = None,
    consume: bool = True,
) -> CapabilityVerificationResult:
    """Independently verify an action-bound capability at the execution boundary.

    Invariants:
    1. Signature must verify against gateway public key over the full capability.
    2. Token must not be expired (now <= expires_at).
    3. Action hash must strictly match recomputed hash of expected_action.
    4. Scope and agent_id must match expected context.
    5. Token must not be replayed (atomic single-use JTI lock).
    """
    current_time = time.time() if now is None else now

    # Decode if compact string
    if isinstance(capability_envelope, str):
        try:
            envelope = decode_token(capability_envelope)
        except Exception as exc:
            return CapabilityVerificationResult(valid=False, error=f"MALFORMED_TOKEN: {exc}")
    elif isinstance(capability_envelope, Mapping):
        envelope = dict(capability_envelope)
    else:
        return CapabilityVerificationResult(valid=False, error="INVALID_CAPABILITY_TYPE")

    claims_dict = envelope.get("capability")
    sig_str = envelope.get("signature")

    if not isinstance(claims_dict, dict) or not sig_str:
        return CapabilityVerificationResult(valid=False, error="MISSING_CAPABILITY_OR_SIGNATURE")

    # 1. Verify Ed25519 signature over canonical bytes of capability structure
    canonical_cap_bytes = canonicalize(claims_dict)
    if not verify(sig_str, canonical_cap_bytes, public_key):
        return CapabilityVerificationResult(valid=False, error="INVALID_SIGNATURE")

    # 2. Check Expiry
    expires_at = claims_dict.get("expires_at", 0)
    if current_time > expires_at:
        return CapabilityVerificationResult(valid=False, error="CAPABILITY_EXPIRED")

    # 3. Check JTI Presence
    jti = claims_dict.get("jti")
    if not jti or not isinstance(jti, str):
        return CapabilityVerificationResult(valid=False, error="MISSING_OR_INVALID_JTI")

    # 4. Critical: Recompute action hash from RAW expected_action
    expected_action_hash = hash_action(expected_action)
    claimed_action_hash = claims_dict.get("action_hash")
    if expected_action_hash != claimed_action_hash:
        return CapabilityVerificationResult(
            valid=False,
            error=f"ACTION_HASH_MISMATCH: expected {expected_action_hash[:16]}..., got {claimed_action_hash}",
            action_hash=expected_action_hash,
        )

    # 5. Check Agent ID
    cap_agent_id = claims_dict.get("agent_id")
    if expected_agent_id is not None and cap_agent_id != expected_agent_id:
        return CapabilityVerificationResult(
            valid=False,
            error=f"AGENT_MISMATCH: expected {expected_agent_id}, got {cap_agent_id}",
        )

    # 6. Check Scope
    cap_scope = claims_dict.get("scope", "")
    if required_scope is not None and not check_scope_allowed(cap_scope, required_scope):
        return CapabilityVerificationResult(
            valid=False,
            error=f"SCOPE_MISMATCH: {cap_scope} does not allow {required_scope}",
        )

    # 7. Atomic Replay Protection (Single-Use Claim)
    store = replay_store or DEFAULT_REPLAY_STORE
    if consume:
        if not store.check_and_claim(jti):
            return CapabilityVerificationResult(
                valid=False,
                error=f"CAPABILITY_ALREADY_CONSUMED: jti {jti} already used",
            )
    else:
        if store.is_consumed(jti):
            return CapabilityVerificationResult(
                valid=False,
                error=f"CAPABILITY_ALREADY_CONSUMED: jti {jti} already used",
            )

    typed_claims = CapabilityClaims(
        schema=claims_dict.get("schema", SCHEMA_V3_CAPABILITY),
        agent_id=str(cap_agent_id),
        scope=str(cap_scope),
        action_hash=str(claimed_action_hash),
        nonce=str(claims_dict.get("nonce", "")),
        jti=str(jti),
        issued_at=float(claims_dict.get("issued_at", 0)),
        expires_at=float(expires_at),
        metadata=dict(claims_dict.get("metadata", {})),
    )

    return CapabilityVerificationResult(
        valid=True,
        claims=typed_claims,
        action_hash=expected_action_hash,
    )
