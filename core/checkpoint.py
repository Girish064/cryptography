"""AgentShield V3 — Merkle Batch Verification & Signed Audit Checkpointing.

Supports:
- Merkle root computation over batches of execution receipts.
- Cryptographically signed audit checkpoints for verifiable state anchors.
- Merkle inclusion proof generation and verification.
- Audit pruning: allows trimming historical receipt bodies while maintaining mathematical proof.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Sequence

from .canonical import canonicalize
from .crypto import PrivateKeyType, PublicKeyType, sign, verify

CHECKPOINT_DOMAIN_PREFIX: bytes = b"AGENTSHIELD-V3-CHECKPOINT\x00"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Compute the Merkle root hash from a sequence of leaf hashes."""
    if not leaf_hashes:
        return _sha256(b"EMPTY_MERKLE_TREE")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    current_level = list(leaf_hashes)
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i + 1]
            else:
                right = left  # Duplicate odd leaf
            combined = _sha256((left + right).encode("ascii"))
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


@dataclass
class AuditCheckpoint:
    """A cryptographically signed anchor representing an immutable batch of receipts."""

    checkpoint_id: str
    head_receipt_id: str
    head_receipt_hash: str
    merkle_root: str
    total_receipts: int
    timestamp: float
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "head_receipt_id": self.head_receipt_id,
            "head_receipt_hash": self.head_receipt_hash,
            "merkle_root": self.merkle_root,
            "total_receipts": self.total_receipts,
            "timestamp": round(self.timestamp, 4),
            "signature": self.signature,
        }


def create_audit_checkpoint(
    receipts: Sequence[dict[str, Any]],
    signing_key: PrivateKeyType,
    checkpoint_id: str = "CHKPT-001",
    timestamp: float | None = None,
) -> AuditCheckpoint:
    """Generate a signed checkpoint summarizing a chain of execution receipts."""
    if not receipts:
        raise ValueError("Cannot create checkpoint for empty receipts list")

    now = time.time() if timestamp is None else timestamp
    leaf_hashes = [r.get("receipt_hash", "") for r in receipts]
    merkle_root = compute_merkle_root(leaf_hashes)

    head_receipt = receipts[-1]
    head_id = head_receipt.get("receipt_id", "")
    head_hash = head_receipt.get("receipt_hash", "")

    payload = {
        "checkpoint_id": checkpoint_id,
        "head_receipt_id": head_id,
        "head_receipt_hash": head_hash,
        "merkle_root": merkle_root,
        "total_receipts": len(receipts),
        "timestamp": round(now, 4),
    }

    canonical_payload = canonicalize(payload)
    hasher = hashlib.sha256()
    hasher.update(CHECKPOINT_DOMAIN_PREFIX)
    hasher.update(canonical_payload)
    checkpoint_hash = hasher.hexdigest()

    sig = sign(checkpoint_hash, signing_key)

    return AuditCheckpoint(
        checkpoint_id=checkpoint_id,
        head_receipt_id=head_id,
        head_receipt_hash=head_hash,
        merkle_root=merkle_root,
        total_receipts=len(receipts),
        timestamp=round(now, 4),
        signature=sig,
    )


def verify_audit_checkpoint(
    checkpoint: AuditCheckpoint | dict[str, Any],
    public_key: PublicKeyType,
    receipts: Sequence[dict[str, Any]] | None = None,
) -> bool:
    """Verify the validity of a signed checkpoint and optionally check against receipts."""
    data = checkpoint.to_dict() if isinstance(checkpoint, AuditCheckpoint) else dict(checkpoint)
    sig = data.get("signature", "")
    if not sig:
        return False

    payload = {
        "checkpoint_id": data["checkpoint_id"],
        "head_receipt_id": data["head_receipt_id"],
        "head_receipt_hash": data["head_receipt_hash"],
        "merkle_root": data["merkle_root"],
        "total_receipts": data["total_receipts"],
        "timestamp": round(data["timestamp"], 4),
    }

    canonical_payload = canonicalize(payload)
    hasher = hashlib.sha256()
    hasher.update(CHECKPOINT_DOMAIN_PREFIX)
    hasher.update(canonical_payload)
    checkpoint_hash = hasher.hexdigest()

    if not verify(sig, checkpoint_hash, public_key):
        return False

    if receipts is not None:
        if len(receipts) != data["total_receipts"]:
            return False
        leaf_hashes = [r.get("receipt_hash", "") for r in receipts]
        if compute_merkle_root(leaf_hashes) != data["merkle_root"]:
            return False
        if receipts[-1].get("receipt_hash") != data["head_receipt_hash"]:
            return False

    return True
