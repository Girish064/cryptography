# AgentShield V3 — Cryptographic Trust & Integrity Protocol

**Owner:** GIRISH — Cryptography & Trust Engineering  
**Tagline:** *Don't just detect — mathematically guarantee the boundary.*

This repository contains the official, verified cryptographic security engine for **AgentShield V3**. It enforces zero-trust execution for AI agent actions, providing deterministic action fingerprinting, Ed25519 action-bound capabilities, single-use atomic replay protection, and immutable hash-chained execution receipts.

---

## 🔐 Core Architecture & Responsibilities

1. **Deterministic Action Fingerprinting (`core/canonical.py`)**:
   - RFC 8785 strict canonical JSON serialization.
   - Unicode NFC normalization.
   - Recomputes SHA-256 action hash with domain separator `AGENTSHIELD-V3-ACTION\x00`.
   - Field ordering invariance: changing dictionary order produces identical hashes; changing values alters the hash.

2. **Ed25519 Action-Bound Capabilities (`core/capability.py`)**:
   - Signs the **full capability structure** (`agent_id`, `scope`, `action_hash`, `nonce`, `jti`, `expires_at`, `metadata`).
   - 14-step executor verification: signature check, expiry check, scope check, recomputed action hash matching.
   - Atomic single-use replay protection (JTI claimed on first execution).
   - Compact dot-separated token transport (`<payload_b64>.<signature>`).

3. **Immutable Execution Receipts & Hash-Chaining (`core/receipt.py`)**:
   - Ties execution outcome directly to the capability `jti` and action hash.
   - Hash-chains backward to genesis `0000...`.
   - Tamper-evident: altering, deleting, or reordering any receipt breaks the chain.
   - **Offline Verifiability:** Third parties, auditors, and judges can verify receipts with **ONLY the public key**.

4. **Key Management & Planned Rotation (`core/key_rotation.py`)**:
   - Manages `ACTIVE`, `RETIRED`, and `REVOKED` key states.
   - Retired keys verify historical receipts; revoked keys fail immediately.

5. **Merkle Batch Checkpoints (`core/checkpoint.py`)**:
   - Computes Merkle root over batches of receipts.
   - Signed audit checkpoints for pruning historical receipts while preserving cryptographic proof.

---

## 🚀 Quickstart for Collaborators (Alok, Pavan, Gururaj)

### 1. Installation
```bash
git clone https://github.com/Girish064/cryptography.git
cd cryptography
pip install -r requirements.txt
```

### 2. Run All Cryptographic Tests (18/18 Passing)
```bash
pytest tests/test_crypto.py -v
```

### 3. Run Live Interactive Demo
```bash
python demo_v3.py
```

### 4. Standalone Offline Receipt Verifier
```bash
python tools/verify_receipt.py --file <path_to_receipts.json> --public-key <ENFORCER_PUBKEY>
```

---

## 💻 Integration Guide for Alok (Platform & APIs)

```python
from core import (
    generate_keypair,
    issue_capability,
    verify_capability,
    issue_receipt,
    verify_receipt_chain,
    encode_token,
)

# 1. Gateway setup
priv, pub = generate_keypair()

# 2. Issue action-bound capability
cap_envelope = issue_capability(
    action={"action": "customer-actions/refund", "order_id": "ORD-101", "amount": 50000},
    agent_id="agent-01",
    scope="customer-actions/*",
    private_key=priv,
    ttl_seconds=30.0,
)
token = encode_token(cap_envelope)

# 3. Enforcer verifies capability before execution
result = verify_capability(
    capability_envelope=token,
    expected_action={"action": "customer-actions/refund", "order_id": "ORD-101", "amount": 50000},
    public_key=pub,
    required_scope="customer-actions/refund",
)

if not result.valid:
    print(f"[BLOCKED] Execution denied: {result.error}")
else:
    # 4. Execute tool side effect & issue signed receipt
    receipt = issue_receipt(
        cap_jti=result.claims.jti,
        action_hash=result.action_hash,
        result_data={"status": "COMMITTED"},
        ledger_state="COMMITTED",
        private_key=priv,
    )
```

---

## 📁 Repository Structure

```text
├── core/
│   ├── canonical.py       # Deterministic canonical JSON & SHA-256 action hashing
│   ├── crypto.py          # Pure Ed25519 keypair generation, sign & verify
│   ├── capability.py      # Action-bound capability tokens & atomic replay store
│   ├── receipt.py         # Hash-chained execution receipts & offline verifier
│   ├── key_rotation.py    # Key rotation & lifecycle management
│   ├── checkpoint.py      # Merkle batch checkpoints & audit pruning
│   └── __init__.py        # Public API exports
├── tests/
│   └── test_crypto.py     # 18 unit & adversarial tests
├── tools/
│   └── verify_receipt.py  # Standalone offline CLI receipt verifier
├── docs/
│   └── CRYPTO_SPEC_V3.md  # Detailed field-by-field cryptographic specification
├── demo_v3.py             # Interactive live attack demonstration
├── requirements.txt       # Dependencies (cryptography, pytest)
└── pytest.ini             # Test configuration
```
