"""AgentShield V3 — Comprehensive Cryptographic Trust Layer Test Suite.

Verifies:
1. Canonical action hashing determinism and field reordering invariance.
2. Ed25519 signing, verification, and tamper detection.
3. Action-bound capability issuance, verification, tampering rejection, and atomic replay lock.
4. Hash-chained execution receipts and offline verification.
"""

import time
import pytest

from core.canonical import canonicalize, hash_action
from core.crypto import (
    generate_keypair,
    sign,
    verify,
    private_key_to_b64,
    public_key_to_b64,
    private_key_from_b64,
    public_key_from_b64,
)
from core.capability import (
    issue_capability,
    verify_capability,
    encode_token,
    decode_token,
    check_scope_allowed,
    CapabilityReplayStore,
)
from core.receipt import (
    issue_receipt,
    verify_receipt,
    verify_receipt_chain,
    compute_receipt_hash,
    compute_result_hash,
    GENESIS_HASH,
)


# =============================================================================
# 1. CANONICAL ACTION & HASH TESTS
# =============================================================================

def test_canonical_determinism_across_key_orders():
    """Verify that different dictionary key insertion orders produce the identical hash."""
    action_1 = {
        "action": "refund",
        "order_id": "ORD-1234",
        "amount": 50000,
        "details": {"reason": "damaged", "source": "chat"},
    }
    action_2 = {
        "details": {"source": "chat", "reason": "damaged"},
        "amount": 50000,
        "order_id": "ORD-1234",
        "action": "refund",
    }

    bytes_1 = canonicalize(action_1)
    bytes_2 = canonicalize(action_2)
    assert bytes_1 == bytes_2

    hash_1 = hash_action(action_1)
    hash_2 = hash_action(action_2)
    assert hash_1 == hash_2
    assert len(hash_1) == 64


def test_action_hash_changes_on_parameter_mutation():
    """Any modification in parameter payload must yield a completely different hash."""
    action_base = {"action": "refund", "order_id": "ORD-1234", "amount": 50000}
    action_tampered = {"action": "refund", "order_id": "ORD-1234", "amount": 500000}

    assert hash_action(action_base) != hash_action(action_tampered)


def test_canonical_unicode_normalization():
    """Ensure composed and decomposed Unicode forms normalize to identical bytes."""
    # Cafe with acute accent: composed vs decomposed
    action_composed = {"store": "Caf\u00e9"}
    action_decomposed = {"store": "Cafe\u0301"}

    assert canonicalize(action_composed) == canonicalize(action_decomposed)
    assert hash_action(action_composed) == hash_action(action_decomposed)


# =============================================================================
# 2. ED25519 CRYPTOGRAPHY TESTS
# =============================================================================

def test_crypto_keypair_generation_and_export():
    """Verify keypair generation and round-trip base64 serialization."""
    priv_b64, pub_b64 = generate_keypair()
    assert isinstance(priv_b64, str) and len(priv_b64) > 30
    assert isinstance(pub_b64, str) and len(pub_b64) > 30

    priv_obj = private_key_from_b64(priv_b64)
    pub_obj = public_key_from_b64(pub_b64)

    assert private_key_to_b64(priv_obj) == priv_b64
    assert public_key_to_b64(pub_obj) == pub_b64


def test_crypto_sign_and_verify():
    """Verify standard signing and verification with valid and invalid signatures."""
    priv_b64, pub_b64 = generate_keypair()
    msg = "AGENTSHIELD_V3_TEST_MESSAGE"

    signature = sign(msg, priv_b64)
    assert verify(signature, msg, pub_b64) is True

    # Tampered message fails
    assert verify(signature, msg + "_TAMPERED", pub_b64) is False

    # Signature with different key fails
    _, other_pub_b64 = generate_keypair()
    assert verify(signature, msg, other_pub_b64) is False


# =============================================================================
# 3. CAPABILITY TOKEN ISSUANCE & VERIFICATION TESTS
# =============================================================================

def test_capability_issue_and_verify_success():
    """End-to-end happy path: issue capability -> verify against expected action."""
    priv_b64, pub_b64 = generate_keypair()
    action = {"action": "refund", "order_id": "ORD-789", "amount": 50000}
    agent_id = "agent-support-01"
    scope = "customer-actions/refund"

    cap = issue_capability(
        action=action,
        agent_id=agent_id,
        scope=scope,
        private_key=priv_b64,
        ttl_seconds=60,
    )

    result = verify_capability(
        capability_envelope=cap,
        expected_action=action,
        public_key=pub_b64,
        expected_agent_id=agent_id,
        required_scope=scope,
    )

    assert result.valid is True
    assert result.claims is not None
    assert result.claims.agent_id == agent_id
    assert result.claims.action_hash == hash_action(action)


def test_capability_rejects_tampered_signature():
    """Tampering with signature must fail verification."""
    priv_b64, pub_b64 = generate_keypair()
    action = {"action": "refund", "order_id": "ORD-789"}

    cap = issue_capability(action, "agent-01", "refund", priv_b64)
    cap["signature"] = cap["signature"][:-4] + "AAAA"

    result = verify_capability(cap, action, pub_b64)
    assert result.valid is False
    assert "INVALID_SIGNATURE" in result.error


def test_capability_rejects_tampered_payload_fields():
    """Tampering with any capability claim (e.g. extending expiry) breaks the signature."""
    priv_b64, pub_b64 = generate_keypair()
    action = {"action": "refund", "order_id": "ORD-789"}

    cap = issue_capability(action, "agent-01", "refund", priv_b64, ttl_seconds=10)
    # Attacker tries to extend expiry
    cap["capability"]["expires_at"] += 99999

    result = verify_capability(cap, action, pub_b64)
    assert result.valid is False
    assert "INVALID_SIGNATURE" in result.error


def test_capability_rejects_action_substitution():
    """An attacker presenting a valid capability for ORD-789 to execute ORD-999 is blocked."""
    priv_b64, pub_b64 = generate_keypair()
    approved_action = {"action": "refund", "order_id": "ORD-789", "amount": 50000}
    malicious_action = {"action": "refund", "order_id": "ORD-789", "amount": 5000000}

    # Gateway approved the 50000 refund
    cap = issue_capability(approved_action, "agent-01", "refund", priv_b64)

    # Attacker attempts to execute the 5000000 refund using the approved capability
    result = verify_capability(cap, expected_action=malicious_action, public_key=pub_b64)
    assert result.valid is False
    assert "ACTION_HASH_MISMATCH" in result.error


def test_capability_rejects_expired_token():
    """An expired capability must immediately fail verification."""
    priv_b64, pub_b64 = generate_keypair()
    action = {"action": "query", "user_id": "U123"}
    now_ts = 1700000000.0

    cap = issue_capability(
        action,
        "agent-01",
        "query",
        priv_b64,
        ttl_seconds=5,
        issued_at=now_ts,
    )

    # Verification attempt 10 seconds later
    result = verify_capability(
        cap,
        action,
        pub_b64,
        now=now_ts + 10.0,
    )
    assert result.valid is False
    assert "CAPABILITY_EXPIRED" in result.error


def test_capability_atomic_single_use_replay_lock():
    """A capability can be consumed exactly once; second attempt fails."""
    priv_b64, pub_b64 = generate_keypair()
    action = {"action": "transfer", "amount": 100}
    replay_store = CapabilityReplayStore()

    cap = issue_capability(action, "agent-01", "transfer", priv_b64)

    # First attempt: succeeds
    res1 = verify_capability(cap, action, pub_b64, replay_store=replay_store)
    assert res1.valid is True

    # Replay attempt: blocked!
    res2 = verify_capability(cap, action, pub_b64, replay_store=replay_store)
    assert res2.valid is False
    assert "CAPABILITY_ALREADY_CONSUMED" in res2.error


def test_capability_compact_token_encoding():
    """Verify dot-separated compact string token transport."""
    priv_b64, pub_b64 = generate_keypair()
    action = {"action": "read", "resource": "docs/sec.txt"}

    cap = issue_capability(action, "agent-01", "read", priv_b64)
    token_str = encode_token(cap)
    assert "." in token_str

    decoded = decode_token(token_str)
    assert decoded["capability"]["jti"] == cap["capability"]["jti"]

    # Verify directly from token string
    res = verify_capability(token_str, action, pub_b64)
    assert res.valid is True


def test_scope_hierarchy_and_wildcard_matching():
    """Verify hierarchical scope matching."""
    assert check_scope_allowed("*", "customer-actions/refund") is True
    assert check_scope_allowed("customer-actions/*", "customer-actions/refund") is True
    assert check_scope_allowed("customer-actions/*", "customer-actions/query") is True
    assert check_scope_allowed("customer-actions/refund", "customer-actions/refund") is True
    assert check_scope_allowed("customer-actions/refund", "customer-actions/delete") is False
    assert check_scope_allowed("customer-actions/*", "system-admin/reboot") is False


# =============================================================================
# 4. EXECUTION RECEIPTS & HASH-CHAINING TESTS
# =============================================================================

def test_receipt_issue_and_verify_single():
    """Verify single receipt issuance and offline mathematical verification."""
    priv_b64, pub_b64 = generate_keypair()
    cap_jti = "CAP-001"
    action_hash = "a" * 64
    result_data = {"status": "SUCCESS", "tx_id": "TX-999"}

    receipt = issue_receipt(
        cap_jti=cap_jti,
        action_hash=action_hash,
        result_data=result_data,
        ledger_state="COMMITTED",
        private_key=priv_b64,
    )

    assert verify_receipt(receipt, pub_b64) is True

    # Tampering with ledger state breaks verification
    receipt_tampered = dict(receipt)
    receipt_tampered["ledger_state"] = "REJECTED"
    assert verify_receipt(receipt_tampered, pub_b64) is False


def test_receipt_hash_chain_verification():
    """Create a chain of 4 receipts and verify uninterrupted integrity."""
    priv_b64, pub_b64 = generate_keypair()
    receipts = []
    prev_hash = GENESIS_HASH

    for i in range(4):
        r = issue_receipt(
            cap_jti=f"CAP-{i}",
            action_hash=f"{i}" * 64,
            result_data={"step": i},
            ledger_state="COMMITTED",
            private_key=priv_b64,
            prev_receipt_hash=prev_hash,
        )
        receipts.append(r)
        prev_hash = r["receipt_hash"]

    # Verify entire chain offline
    valid, msg = verify_receipt_chain(receipts, pub_b64)
    assert valid is True
    assert "VERIFIED_4_RECEIPTS" in msg


def test_receipt_chain_detects_deletion_or_reordering():
    """Tampering with chain continuity (deletion, reordering) is detected immediately."""
    priv_b64, pub_b64 = generate_keypair()
    receipts = []
    prev_hash = GENESIS_HASH

    for i in range(3):
        r = issue_receipt(
            cap_jti=f"CAP-{i}",
            action_hash=f"{i}" * 64,
            result_data={"step": i},
            ledger_state="COMMITTED",
            private_key=priv_b64,
            prev_receipt_hash=prev_hash,
        )
        receipts.append(r)
        prev_hash = r["receipt_hash"]

    # 1. Delete middle receipt (index 1)
    truncated_chain = [receipts[0], receipts[2]]
    valid, msg = verify_receipt_chain(truncated_chain, pub_b64)
    assert valid is False
    assert "CHAIN_BROKEN" in msg

    # 2. Swap receipts order
    swapped_chain = [receipts[1], receipts[0], receipts[2]]
    valid2, msg2 = verify_receipt_chain(swapped_chain, pub_b64)
    assert valid2 is False
    assert "CHAIN_BROKEN" in msg2


# =============================================================================
# 5. KEY ROTATION & CHECKPOINT TESTS (INTERMEDIATE & ADVANCED)
# =============================================================================

from core.key_rotation import KeyRotationManager, KeyState
from core.checkpoint import create_audit_checkpoint, verify_audit_checkpoint, compute_merkle_root


def test_key_rotation_historical_verification_and_revocation():
    """Verify that retired keys still verify historical signatures, but revoked keys fail."""
    mgr = KeyRotationManager()

    # 1. Key 1 is active
    k1 = mgr.generate_and_add_active_key("gw-key-2026-v1")
    msg1 = "historical_transaction_1"
    sig1 = sign(msg1, k1.private_key)

    assert mgr.verify_with_kid("gw-key-2026-v1", sig1, msg1) is True

    # 2. Rotate to Key 2 (Key 1 becomes RETIRED)
    k2 = mgr.rotate_active_key("gw-key-2026-v2")
    assert k1.state == KeyState.RETIRED
    assert k2.state == KeyState.ACTIVE

    # Historical signature with Key 1 must still verify
    assert mgr.verify_with_kid("gw-key-2026-v1", sig1, msg1, allow_retired=True) is True

    # But retired key cannot be used as the active signing key
    assert mgr.get_active_signing_key().kid == "gw-key-2026-v2"

    # 3. Revoke Key 1 -> must fail immediately even for historical records
    mgr.revoke_key("gw-key-2026-v1")
    assert mgr.verify_with_kid("gw-key-2026-v1", sig1, msg1) is False


def test_merkle_checkpoint_creation_and_verification():
    """Verify creation and signature verification of Merkle batch checkpoints."""
    priv_b64, pub_b64 = generate_keypair()
    receipts = []
    prev_hash = GENESIS_HASH

    for i in range(5):
        r = issue_receipt(
            cap_jti=f"CAP-{i}",
            action_hash=f"{i}" * 64,
            result_data={"step": i},
            ledger_state="COMMITTED",
            private_key=priv_b64,
            prev_receipt_hash=prev_hash,
        )
        receipts.append(r)
        prev_hash = r["receipt_hash"]

    checkpoint = create_audit_checkpoint(receipts, priv_b64, checkpoint_id="CHKPT-TEST-001")
    assert checkpoint.total_receipts == 5
    assert len(checkpoint.merkle_root) == 64

    # Verification passes with intact receipts
    assert verify_audit_checkpoint(checkpoint, pub_b64, receipts=receipts) is True

    # Tampering with any receipt fails Merkle check
    tampered_receipts = [dict(r) for r in receipts]
    tampered_receipts[2]["receipt_hash"] = "f" * 64
    assert verify_audit_checkpoint(checkpoint, pub_b64, receipts=tampered_receipts) is False
