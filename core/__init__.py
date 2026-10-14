"""AgentShield V3 — Core Cryptographic Trust Layer Package."""

from .canonical import (
    canonicalize,
    hash_action,
    ACTION_DOMAIN_PREFIX,
)
from .crypto import (
    generate_keypair,
    sign,
    verify,
    private_key_to_b64,
    public_key_to_b64,
    private_key_from_b64,
    public_key_from_b64,
    load_keypair_from_env,
)
from .capability import (
    CapabilityClaims,
    CapabilityVerificationResult,
    CapabilityReplayStore,
    issue_capability,
    verify_capability,
    encode_token,
    decode_token,
    check_scope_allowed,
)
from .receipt import (
    issue_receipt,
    verify_receipt,
    verify_receipt_chain,
    compute_receipt_hash,
    compute_result_hash,
    export_receipts_json,
    load_receipts_json,
    GENESIS_HASH,
)
from .key_rotation import (
    KeyRotationManager,
    KeyState,
    KeyMetadata,
)
from .checkpoint import (
    AuditCheckpoint,
    create_audit_checkpoint,
    verify_audit_checkpoint,
    compute_merkle_root,
)

__all__ = [
    # Canonical
    "canonicalize",
    "hash_action",
    "ACTION_DOMAIN_PREFIX",
    # Crypto
    "generate_keypair",
    "sign",
    "verify",
    "private_key_to_b64",
    "public_key_to_b64",
    "private_key_from_b64",
    "public_key_from_b64",
    "load_keypair_from_env",
    # Capability
    "CapabilityClaims",
    "CapabilityVerificationResult",
    "CapabilityReplayStore",
    "issue_capability",
    "verify_capability",
    "encode_token",
    "decode_token",
    "check_scope_allowed",
    # Receipt
    "issue_receipt",
    "verify_receipt",
    "verify_receipt_chain",
    "compute_receipt_hash",
    "compute_result_hash",
    "export_receipts_json",
    "load_receipts_json",
    "GENESIS_HASH",
    # Key Rotation
    "KeyRotationManager",
    "KeyState",
    "KeyMetadata",
    # Checkpoints & Merkle
    "AuditCheckpoint",
    "create_audit_checkpoint",
    "verify_audit_checkpoint",
    "compute_merkle_root",
]
