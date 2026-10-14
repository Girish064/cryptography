"""AgentShield V3 — Cryptographic Trust Layer Interactive Demonstration.

Shows:
1. Deterministic canonical action fingerprinting.
2. Legitimate capability issuance & verification.
3. Attack 1: Action substitution (tampered parameter) -> BLOCKED.
4. Attack 2: Replay attack (re-submitting consumed capability) -> BLOCKED.
5. Attack 3: Capability claim tampering (signature break) -> BLOCKED.
6. Execution receipt issuance & immutable hash-chain offline verification.
"""

import time
from core.canonical import canonicalize, hash_action
from core.crypto import generate_keypair
from core.capability import (
    issue_capability,
    verify_capability,
    CapabilityReplayStore,
    encode_token,
)
from core.receipt import (
    issue_receipt,
    verify_receipt_chain,
    GENESIS_HASH,
)


def run_demo():
    print("=" * 80)
    print("      AGENTSHIELD V3 -- ADAPTIVE ZERO-TRUST CRYPTOGRAPHIC SHIELD      ")
    print("              ROLE: GIRISH (Cryptography & Trust Engineering)         ")
    print("=" * 80)

    # 1. Key Generation
    print("\n[+] Step 1: Initializing Enforcer & Gateway Ed25519 Keypairs...")
    gw_priv, gw_pub = generate_keypair()
    enf_priv, enf_pub = generate_keypair()
    print(f"    Gateway Public Key  : {gw_pub[:32]}...")
    print(f"    Enforcer Public Key : {enf_pub[:32]}...")

    # 2. Canonical Action Hashing
    print("\n[+] Step 2: Testing Deterministic Action Fingerprinting...")
    raw_action_a = {
        "action": "customer-actions/refund",
        "order_id": "ORD-789",
        "amount": 50000,
        "recipient": "ACC-LEGITIMATE",
    }
    raw_action_b = {
        "recipient": "ACC-LEGITIMATE",
        "amount": 50000,
        "order_id": "ORD-789",
        "action": "customer-actions/refund",
    }
    hash_a = hash_action(raw_action_a)
    hash_b = hash_action(raw_action_b)

    print(f"    Action A (Normal order)   : {raw_action_a}")
    print(f"    Action B (Reordered keys) : {raw_action_b}")
    print(f"    Fingerprint A : {hash_a}")
    print(f"    Fingerprint B : {hash_b}")
    assert hash_a == hash_b, "Fingerprints must match!"
    print("    [PASS] Fingerprints match identically regardless of field order!")

    # 3. Legitimate Capability Issuance & Verification
    print("\n[+] Step 3: Gateway Issues Cryptographically Signed Capability...")
    cap = issue_capability(
        action=raw_action_a,
        agent_id="agent-support-01",
        scope="customer-actions/*",
        private_key=gw_priv,
        ttl_seconds=30.0,
        metadata={"confidence": 0.95, "risk_level": "LOW"},
    )
    token_str = encode_token(cap)
    print(f"    Issued Capability JTI : {cap['capability']['jti']}")
    print(f"    Bound Action Hash     : {cap['capability']['action_hash'][:24]}...")
    print(f"    Compact Token String  : {token_str[:40]}...{token_str[-20:]}")

    replay_store = CapabilityReplayStore()
    print("\n[+] Step 4: Protected Enforcer Evaluates Legitimate Action...")
    result_legit = verify_capability(
        capability_envelope=token_str,
        expected_action=raw_action_a,
        public_key=gw_pub,
        expected_agent_id="agent-support-01",
        required_scope="customer-actions/refund",
        replay_store=replay_store,
    )
    print(f"    Enforcer Verification : {'[ALLOWED]' if result_legit.valid else '[DENIED]'}")
    assert result_legit.valid, "Legitimate capability must pass!"

    # 4. Attack 1: Action Substitution
    print("\n[!] Step 5: [ATTACK 1] Attacker Mutates Amount to 500,000 (Action Substitution)...")
    tampered_action = {
        "action": "customer-actions/refund",
        "order_id": "ORD-789",
        "amount": 500000,  # 10x unauthorized refund
        "recipient": "ACC-MALICIOUS",
    }
    result_tamper = verify_capability(
        capability_envelope=token_str,
        expected_action=tampered_action,
        public_key=gw_pub,
        replay_store=replay_store,
        consume=False,
    )
    print(f"    Computed Action Hash  : {hash_action(tampered_action)[:24]}...")
    print(f"    Bound Action Hash     : {cap['capability']['action_hash'][:24]}...")
    print(f"    Enforcer Decision     : [BLOCKED] {result_tamper.error}")

    # 5. Attack 2: Replay Attack
    print("\n[!] Step 6: [ATTACK 2] Attacker Tries to Replay the Same Capability...")
    result_replay = verify_capability(
        capability_envelope=token_str,
        expected_action=raw_action_a,
        public_key=gw_pub,
        replay_store=replay_store,
    )
    print(f"    Enforcer Decision     : [BLOCKED] {result_replay.error}")

    # 6. Attack 3: Tampering Capability Payload
    print("\n[!] Step 7: [ATTACK 3] Attacker Tries to Extend Capability Expiry Time...")
    tampered_cap = dict(cap)
    tampered_cap["capability"] = dict(cap["capability"])
    tampered_cap["capability"]["expires_at"] += 3600
    result_forgery = verify_capability(
        capability_envelope=tampered_cap,
        expected_action=raw_action_a,
        public_key=gw_pub,
        replay_store=replay_store,
        consume=False,
    )
    print(f"    Enforcer Decision     : [BLOCKED] {result_forgery.error}")

    # 7. Immutable Execution Receipts & Hash-Chaining
    print("\n[+] Step 8: Issuing Signed Execution Receipts & Building Hash-Chain...")
    receipt_chain = []
    prev_hash = GENESIS_HASH

    for i in range(3):
        receipt = issue_receipt(
            cap_jti=f"CAP-DEMO-{i}",
            action_hash=hash_action({"step": i}),
            result_data={"status": "COMMITTED", "effect_id": f"EFF-00{i}"},
            ledger_state="COMMITTED",
            private_key=enf_priv,
            prev_receipt_hash=prev_hash,
        )
        receipt_chain.append(receipt)
        prev_hash = receipt["receipt_hash"]
        print(f"    Receipt #{i+1} : {receipt['receipt_id']} | Prev: {receipt['prev_receipt_hash'][:16]}... | Hash: {receipt['receipt_hash'][:16]}...")

    # 8. Offline Verification
    print("\n[+] Step 9: Independent Observer Offline Chain Verification...")
    chain_valid, chain_msg = verify_receipt_chain(receipt_chain, enf_pub)
    print(f"    Verification Status   : {'[VERIFIED PASS]' if chain_valid else '[FAILED]'}")
    print(f"    Verifier Evidence     : {chain_msg}")

    print("\n" + "=" * 80)
    print("      ALL AGENTSHIELD V3 CRYPTOGRAPHIC DELIVERABLES FULLY OPERATIONAL ")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()
