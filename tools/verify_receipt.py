"""AgentShield V3 — Standalone Offline Receipt Verifier CLI.

Enables an auditor, judge, or third-party observer to independently verify
an exported execution receipt chain using ONLY the public key.
Zero network access, zero server dependencies, pure math.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct CLI execution
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.crypto import public_key_from_b64
from core.receipt import verify_receipt_chain


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AgentShield V3: Standalone Offline Receipt Chain Verifier",
    )
    parser.add_argument(
        "--file",
        "-f",
        required=True,
        help="Path to the JSON file containing the exported receipt chain",
    )
    parser.add_argument(
        "--public-key",
        "-k",
        required=True,
        help="Base64-encoded Ed25519 public key of the Enforcer",
    )

    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"[!] Error: File not found: {file_path}", file=sys.stderr)
        return 1

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            receipts = json.load(f)
    except Exception as exc:
        print(f"[!] Error reading JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(receipts, list):
        print("[!] Error: Expected a JSON array of receipt objects.", file=sys.stderr)
        return 1

    try:
        pub_key = public_key_from_b64(args.public_key)
    except Exception as exc:
        print(f"[!] Error parsing public key: {exc}", file=sys.stderr)
        return 1

    print("=" * 70)
    print("      AGENTSHIELD V3 -- OFFLINE CRYPTOGRAPHIC RECEIPT VERIFIER        ")
    print("=" * 70)
    print(f"Receipt Chain File  : {file_path.resolve()}")
    print(f"Receipts in Chain   : {len(receipts)}")
    print(f"Public Key (prefix) : {args.public_key[:24]}...")
    print("-" * 70)

    valid, message = verify_receipt_chain(receipts, pub_key)

    if valid:
        print("[PASS] VERIFICATION SUCCEEDED:")
        print(f"    - All {len(receipts)} receipt cryptographic signatures are VALID.")
        print("    - All hash-links are intact (unbroken chain to genesis).")
        print("    - Zero evidence tampering, deletion, or reordering detected.")
        print("=" * 70)
        return 0
    else:
        print("[FAIL] VERIFICATION FAILED:")
        print(f"    - Reason: {message}")
        print("=" * 70)
        return 2


if __name__ == "__main__":
    sys.exit(main())
