"""AgentShield V3 — Immutable Execution Receipts & Hash-Chained Verifiable Trust.

Provides cryptographic execution evidence that can be independently verified
offline with zero API access, proving that an authorized action took place
and was recorded into the execution ledger.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Optional, Sequence, Union

from .canonical import canonicalize
from .crypto import PrivateKeyType, PublicKeyType, sign, verify

SCHEMA_V3_RECEIPT = "agentshield.v3.receipt"
GENESIS_HASH: str = "0" * 64
RECEIPT_DOMAIN_PREFIX: bytes = b"AGENTSHIELD-V3-RECEIPT\x00"


def compute_result_hash(result_data: Any) -> str:
    """Compute deterministic SHA-256 hash of execution result payload."""
    canonical_result = canonicalize(result_data)
    hasher = hashlib.sha256()
    hasher.update(b"AGENTSHIELD-V3-RESULT\x00")
    hasher.update(canonical_result)
    return hasher.hexdigest()


def compute_receipt_hash(receipt_content: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of the canonical receipt fields.

    Excludes 'signature' and 'receipt_hash' so the hash is mathematically self-contained.
    """
    fields_to_hash = {
        "schema": receipt_content.get("schema", SCHEMA_V3_RECEIPT),
        "receipt_id": receipt_content["receipt_id"],
        "cap_jti": receipt_content["cap_jti"],
        "action_hash": receipt_content["action_hash"],
        "result_hash": receipt_content["result_hash"],
        "ledger_state": receipt_content["ledger_state"],
        "timestamp": round(receipt_content["timestamp"], 4),
        "prev_receipt_hash": receipt_content["prev_receipt_hash"],
    }
    canonical_bytes = canonicalize(fields_to_hash)
    hasher = hashlib.sha256()
    hasher.update(RECEIPT_DOMAIN_PREFIX)
    hasher.update(canonical_bytes)
    return hasher.hexdigest()


def issue_receipt(
    cap_jti: str,
    action_hash: str,
    result_data: Any,
    ledger_state: str,
    private_key: PrivateKeyType,
    *,
    prev_receipt_hash: str = GENESIS_HASH,
    receipt_id: Optional[str] = None,
    timestamp: Optional[float] = None,
) -> dict[str, Any]:
    """Create and sign a new execution receipt, chaining it to the previous receipt hash."""
    now = time.time() if timestamp is None else timestamp
    r_id = receipt_id or f"RCPT-{secrets.token_hex(8)}"
    res_hash = compute_result_hash(result_data)

    receipt_dict: dict[str, Any] = {
        "schema": SCHEMA_V3_RECEIPT,
        "receipt_id": r_id,
        "cap_jti": cap_jti,
        "action_hash": action_hash,
        "result_hash": res_hash,
        "ledger_state": ledger_state,
        "timestamp": round(now, 4),
        "prev_receipt_hash": prev_receipt_hash,
    }

    # 1. Calculate the unique cryptographic receipt hash
    r_hash = compute_receipt_hash(receipt_dict)
    receipt_dict["receipt_hash"] = r_hash

    # 2. Sign the receipt hash with the Enforcer's Ed25519 private key
    signature_str = sign(r_hash, private_key)
    receipt_dict["signature"] = signature_str

    return receipt_dict


def verify_receipt(
    receipt: dict[str, Any],
    public_key: PublicKeyType,
    *,
    expected_prev_hash: Optional[str] = None,
) -> bool:
    """Independently verify an execution receipt offline.

    Checks:
    1. Recomputed receipt hash matches receipt['receipt_hash'].
    2. Signature over receipt_hash is valid under public_key.
    3. prev_receipt_hash matches expected_prev_hash (if provided).
    """
    if not isinstance(receipt, dict):
        return False

    claimed_hash = receipt.get("receipt_hash")
    sig = receipt.get("signature")
    if not claimed_hash or not sig:
        return False

    # 1. Recompute receipt hash
    try:
        expected_hash = compute_receipt_hash(receipt)
        if expected_hash != claimed_hash:
            return False
    except (KeyError, TypeError, ValueError):
        return False

    # 2. Verify signature over the receipt hash
    if not verify(sig, claimed_hash, public_key):
        return False

    # 3. Optional previous hash link check
    if expected_prev_hash is not None:
        if receipt.get("prev_receipt_hash") != expected_prev_hash:
            return False

    return True


def verify_receipt_chain(
    receipts: Sequence[dict[str, Any]],
    public_key: PublicKeyType,
    *,
    genesis_prev_hash: str = GENESIS_HASH,
) -> tuple[bool, str]:
    """Verify an entire immutable chain of receipts offline.

    Ensures:
    - Every individual receipt signature and hash is intact.
    - No receipt was deleted, inserted, modified, or reordered.
    - Chain links backward seamlessly to the genesis hash.
    """
    if not receipts:
        return (True, "EMPTY_CHAIN")

    expected_prev = genesis_prev_hash

    for idx, r in enumerate(receipts):
        r_id = r.get("receipt_id", f"index-{idx}")

        # Check link to previous receipt
        actual_prev = r.get("prev_receipt_hash")
        if actual_prev != expected_prev:
            return (
                False,
                f"CHAIN_BROKEN at {r_id}: expected prev_hash {expected_prev[:16]}..., got {actual_prev}",
            )

        # Verify individual receipt signature and recomputed hash
        if not verify_receipt(r, public_key):
            return False, f"INVALID_RECEIPT_SIGNATURE_OR_HASH at {r_id}"

        expected_prev = r.get("receipt_hash", "")

    return (True, f"VERIFIED_{len(receipts)}_RECEIPTS")


def export_receipts_json(receipts: Sequence[dict[str, Any]], file_path: str) -> None:
    """Export receipt chain to a portable JSON proof file for offline auditing."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(list(receipts), f, indent=2)


def load_receipts_json(file_path: str) -> list[dict[str, Any]]:
    """Load portable receipt chain proof from JSON file."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)
