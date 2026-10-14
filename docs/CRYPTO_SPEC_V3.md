# AgentShield V3 — Cryptographic Trust & Integrity Specification

**Role:** GIRISH — Cryptography & Trust Engineering  
**Mission:** Make trust mathematically verifiable. Every action proves itself.

---

## 1. Overview of Girish's Scope

Girish owns the **mathematical security foundation** of AgentShield V3.
Our responsibility is ensuring that:
1. An approved action cannot be altered or substituted.
2. Authorization cannot be replayed or extended beyond its intended scope or lifespan.
3. Execution produces immutable, hash-chained receipts that any third party can verify offline with **only a public key**.
4. Keys can be rotated without breaking historical verification.

---

## 2. Field-by-Field Security Matrix

### 2.1 Capability Token (`core/capability.py`)
Signs the **FULL** capability dictionary—not just the action hash.

| Field | Type | What It Protects / Security Purpose |
|---|---|---|
| `schema` | `string` | Version pinning (`agentshield.v3.capability`). Prevents protocol downgrade or schema confusion attacks. |
| `agent_id` | `string` | Principal identity binding. Prevents Agent A from using a capability granted to Agent B. |
| `scope` | `string` | Delegation boundaries (e.g., `customer-actions/*`). Prevents privilege escalation beyond the authorized namespace. |
| `action_hash` | `string` | Exact SHA-256 canonical action fingerprint. Protects against **Action Substitution (Attack 1)**: altering amounts, recipients, or parameters immediately breaks verification. |
| `nonce` | `string` | High-entropy randomness. Prevents capability hash collisions and rainbow-table attacks. |
| `jti` | `string` | Unique capability identifier. Enforces **Atomic Single-Use Replay Protection (Attack 2)**: consumed on first execution. |
| `issued_at` | `float (UTC)` | Issue timestamp. Prevents pre-dated capabilities and establishes temporal ordering. |
| `expires_at` | `float (UTC)` | Short-lived TTL boundary (seconds). Limits the window of vulnerability if an agent is compromised. |
| `metadata` | `dict` | Contextual policy data (confidence score, risk tier). Used by adaptive policies. |
| `signature` | `string` | Ed25519 signature over canonical bytes of the above fields using Gateway Private Key. |

---

### 2.2 Execution Receipt (`core/receipt.py`)
Each receipt binds the execution result and chains backward to the previous receipt.

| Field | Type | What It Protects / Security Purpose |
|---|---|---|
| `schema` | `string` | Version pinning (`agentshield.v3.receipt`). |
| `receipt_id` | `string` | Unique receipt identifier. |
| `cap_jti` | `string` | Ties execution outcome directly back to the capability `jti` that authorized it. |
| `action_hash` | `string` | Binds receipt to the exact action fingerprint. |
| `result_hash` | `string` | SHA-256 hash of the execution outcome. Proves the returned data was not forged or altered. |
| `ledger_state` | `string` | Status in the state store (`COMMITTED`, `REJECTED`, `FAILED`). |
| `timestamp` | `float (UTC)` | UTC timestamp of execution. |
| `prev_receipt_hash` | `string` | Hash of the previous receipt in the ledger (or 64 zeros for Genesis). Creates an **immutable hash chain**. |
| `receipt_hash` | `string` | Self-contained SHA-256 hash of all canonical receipt fields. |
| `signature` | `string` | Ed25519 signature by the Protected Enforcer over `receipt_hash`. |

---

## 3. Cryptographic Invariants (Non-Negotiable)

1. **Never Trust Caller-Supplied Hashes:** The Enforcer **always recomputes** the action hash from the raw incoming action payload:
   $$\text{hash} = \text{SHA256}(\text{"AGENTSHIELD-V3-ACTION\x00"} + \text{canonicalize}(\text{raw\_action}))$$
2. **Sign the Entire Structure:** Capabilities sign all claims, preventing adversaries from modifying scopes, dates, or nonces without invalidating the signature.
3. **Fail-Closed Execution:** Any signature failure, expired TTL, scope mismatch, or replay attempt halts execution immediately before any side effect occurs.
4. **Offline Verifiability:** Execution receipts require **zero system login or network access** to verify. An auditor only needs the Enforcer's public key.

---

## 4. Key Management & Rotation (`core/key_rotation.py`)

- **Active Keys:** Used to sign new capabilities or receipts.
- **Retired Keys:** Retained to verify historical receipts or capabilities issued prior to retirement. Cannot sign new artifacts.
- **Revoked Keys:** Marked compromised; rejected immediately for both signing and verification.

---

## 5. Merkle Batching & Checkpoints (`core/checkpoint.py`)

For high-throughput systems:
- Receipts are grouped into Merkle trees.
- A signed `AuditCheckpoint` captures the Merkle root, head receipt hash, and total count.
- **Audit Pruning:** Intermediate receipt bodies can be archived or trimmed while the cryptographic proof of inclusion remains provable against the signed checkpoint.

---

## 6. Honest Limitations & Threat Boundaries

1. **Replay Across Distributed Enforcers:** Replay protection requires a synchronized atomic store (in-memory for single-node, Redis `SET NX` for distributed).
2. **Attestation vs Physical Effect:** The receipt signature proves the Enforcer executed the action; it attests to the Enforcer's operation. Verification of external third-party tools relies on the Enforcer's integrity.
3. **Clock Skew:** Enforcers and gateways must maintain NTP synchronization to ensure TTL expiration checks behave consistently.
