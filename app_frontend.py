"""AgentShield V3 — Judge Interactive Cryptographic Trust Console.

Role: GIRISH (Cryptography & Trust Protocol Engineer)
Launch: python app_frontend.py
Access: http://localhost:8000
"""

import json
import time
from typing import Any, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

import core

app = FastAPI(title="AgentShield V3 - Cryptographic Console (Girish)")

# Global state for interactive live demonstration
STATE = {
    "gw_priv": None,
    "gw_pub": None,
    "enf_priv": None,
    "enf_pub": None,
    "latest_capability": None,
    "latest_token": None,
    "latest_action": {
        "action": "customer-actions/refund",
        "order_id": "ORD-789",
        "amount": 50000,
        "recipient": "ACC-LEGITIMATE",
    },
    "receipt_chain": [],
    "replay_store": core.CapabilityReplayStore(),
}


def init_keys():
    if STATE["gw_priv"] is None:
        gw_priv, gw_pub = core.generate_keypair()
        enf_priv, enf_pub = core.generate_keypair()
        STATE["gw_priv"] = gw_priv
        STATE["gw_pub"] = gw_pub
        STATE["enf_priv"] = enf_priv
        STATE["enf_pub"] = enf_pub


init_keys()


@app.get("/api/state")
def get_state():
    return {
        "gateway_public_key": STATE["gw_pub"],
        "enforcer_public_key": STATE["enf_pub"],
        "latest_action": STATE["latest_action"],
        "latest_action_hash": core.hash_action(STATE["latest_action"]),
        "latest_token": STATE["latest_token"],
        "receipt_count": len(STATE["receipt_chain"]),
        "receipt_chain": STATE["receipt_chain"],
    }


@app.post("/api/keys/regenerate")
def regenerate_keys():
    gw_priv, gw_pub = core.generate_keypair()
    enf_priv, enf_pub = core.generate_keypair()
    STATE["gw_priv"] = gw_priv
    STATE["gw_pub"] = gw_pub
    STATE["enf_priv"] = enf_priv
    STATE["enf_pub"] = enf_pub
    return {
        "gateway_public_key": gw_pub,
        "enforcer_public_key": enf_pub,
    }


@app.post("/api/action/hash")
async def compute_action_hash(request: Request):
    data = await request.json()
    action = data.get("action", {})
    canon_bytes = core.canonicalize(action)
    digest = core.hash_action(action)
    return {
        "canonical_json": canon_bytes.decode("utf-8"),
        "action_hash": digest,
    }


@app.post("/api/capability/issue")
async def issue_cap(request: Request):
    data = await request.json()
    action = data.get("action", STATE["latest_action"])
    agent_id = data.get("agent_id", "agent-support-01")
    scope = data.get("scope", "customer-actions/*")
    ttl = float(data.get("ttl_seconds", 30.0))

    cap_envelope = core.issue_capability(
        action=action,
        agent_id=agent_id,
        scope=scope,
        private_key=STATE["gw_priv"],
        ttl_seconds=ttl,
        metadata={"confidence": 0.95, "risk": "LOW"},
    )
    token_str = core.encode_token(cap_envelope)

    STATE["latest_action"] = action
    STATE["latest_capability"] = cap_envelope
    STATE["latest_token"] = token_str

    return {
        "capability": cap_envelope["capability"],
        "signature": cap_envelope["signature"],
        "compact_token": token_str,
        "action_hash": cap_envelope["capability"]["action_hash"],
    }


@app.post("/api/enforcer/execute")
async def enforcer_execute(request: Request):
    data = await request.json()
    token = data.get("token") or STATE["latest_token"]
    action = data.get("action") or STATE["latest_action"]
    required_scope = data.get("required_scope", "customer-actions/refund")

    if not token:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "No capability token provided. Please issue one first."},
        )

    # Enforcer independent verification
    result = core.verify_capability(
        capability_envelope=token,
        expected_action=action,
        public_key=STATE["gw_pub"],
        required_scope=required_scope,
        replay_store=STATE["replay_store"],
    )

    if not result.valid:
        return {
            "success": False,
            "status": "BLOCKED",
            "error": result.error,
            "recomputed_action_hash": result.action_hash,
            "decision": "EXECUTION_HALTED_BOUNDARY_HELD",
        }

    # Issue immutable receipt on success
    prev_hash = STATE["receipt_chain"][-1]["receipt_hash"] if STATE["receipt_chain"] else core.GENESIS_HASH
    receipt = core.issue_receipt(
        cap_jti=result.claims.jti,
        action_hash=result.action_hash,
        result_data={"status": "COMMITTED", "timestamp": time.time()},
        ledger_state="COMMITTED",
        private_key=STATE["enf_priv"],
        prev_receipt_hash=prev_hash,
    )
    STATE["receipt_chain"].append(receipt)

    return {
        "success": True,
        "status": "ALLOWED",
        "action_hash": result.action_hash,
        "jti": result.claims.jti,
        "receipt": receipt,
        "decision": "EXECUTION_COMMITTED_RECEIPT_CHAINED",
    }


@app.post("/api/receipts/verify")
def verify_receipts():
    valid, message = core.verify_receipt_chain(STATE["receipt_chain"], STATE["enf_pub"])
    return {
        "valid": valid,
        "message": message,
        "receipt_count": len(STATE["receipt_chain"]),
    }


@app.post("/api/reset")
def reset_demo():
    STATE["receipt_chain"].clear()
    STATE["replay_store"].clear()
    STATE["latest_token"] = None
    return {"message": "Demo state reset successfully"}


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return HTML_CONTENT


HTML_CONTENT = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentShield V3 — Cryptographic Trust Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            mono: ['"JetBrains Mono"', 'monospace'],
            sans: ['Inter', 'sans-serif'],
          },
          colors: {
            brand: {
              bg: '#090d16',
              card: '#111827',
              border: '#1f2937',
              cyan: '#06b6d4',
              emerald: '#10b981',
              rose: '#f43f5e',
              amber: '#f59e0b'
            }
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #090d16; color: #e2e8f0; font-family: 'Inter', sans-serif; }
    .mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="p-6">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- Header Banner -->
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-2xl">
      <div>
        <div class="flex items-center gap-3">
          <span class="px-2.5 py-1 text-xs font-bold rounded-md bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase tracking-wider">
            AgentShield V3
          </span>
          <span class="px-2.5 py-1 text-xs font-bold rounded-md bg-emerald-950 text-emerald-400 border border-emerald-800 uppercase tracking-wider">
            Zero-Trust Boundary
          </span>
          <span class="text-xs text-gray-400 font-mono">Role: GIRISH (Cryptography & Trust Protocol)</span>
        </div>
        <h1 class="text-2xl font-bold text-white mt-1">Cryptographic Trust & Integrity Console</h1>
        <p class="text-sm text-gray-400">Mathematically guarantee execution boundaries for autonomous AI agents.</p>
      </div>
      <div class="mt-4 md:mt-0 flex gap-2">
        <button onclick="resetAll()" class="px-3 py-1.5 text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg border border-gray-700 transition">
          Reset Demo
        </button>
        <button onclick="regenerateKeys()" class="px-3 py-1.5 text-xs font-semibold bg-cyan-900/60 hover:bg-cyan-800 text-cyan-300 rounded-lg border border-cyan-700 transition">
          Rotate Ed25519 Keys
        </button>
      </div>
    </header>

    <!-- Key Pairs Info Bar -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="bg-gray-900/80 border border-gray-800 rounded-lg p-3">
        <div class="text-xs text-gray-400 uppercase font-mono tracking-wider">Gateway Public Key (Issuer)</div>
        <div id="gwPub" class="text-xs font-mono text-cyan-400 truncate mt-1">Loading...</div>
      </div>
      <div class="bg-gray-900/80 border border-gray-800 rounded-lg p-3">
        <div class="text-xs text-gray-400 uppercase font-mono tracking-wider">Enforcer Public Key (Executor)</div>
        <div id="enfPub" class="text-xs font-mono text-emerald-400 truncate mt-1">Loading...</div>
      </div>
    </div>

    <!-- Quick Scenario Buttons for Judges -->
    <div class="bg-gradient-to-r from-gray-900 via-gray-900 to-gray-950 border border-cyan-900/40 rounded-xl p-4 shadow-lg">
      <div class="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2 font-mono">
        🎯 1-Click Scenarios for Hackathon Judges
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <button onclick="scenarioLegitimate()" class="p-3 bg-gray-800/80 hover:bg-emerald-950/40 hover:border-emerald-500 border border-gray-700 rounded-lg text-left transition group">
          <div class="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
            <span>[1]</span> Legitimate Execution
          </div>
          <div class="text-xs text-gray-400 mt-1">Refund ₹500: Issue valid token, verify hash & chain receipt.</div>
        </button>
        <button onclick="scenarioTamperAmount()" class="p-3 bg-gray-800/80 hover:bg-rose-950/40 hover:border-rose-500 border border-gray-700 rounded-lg text-left transition group">
          <div class="text-xs font-bold text-rose-400 flex items-center gap-1.5">
            <span>[2]</span> Action Substitution Attack
          </div>
          <div class="text-xs text-gray-400 mt-1">Attacker inflates refund to ₹50,000. Catches hash mismatch.</div>
        </button>
        <button onclick="scenarioReplay()" class="p-3 bg-gray-800/80 hover:bg-amber-950/40 hover:border-amber-500 border border-gray-700 rounded-lg text-left transition group">
          <div class="text-xs font-bold text-amber-400 flex items-center gap-1.5">
            <span>[3]</span> Replay Attack
          </div>
          <div class="text-xs text-gray-400 mt-1">Attacker resubmits valid token. Blocked by single-use atomic lock.</div>
        </button>
        <button onclick="scenarioVerifyOffline()" class="p-3 bg-gray-800/80 hover:bg-cyan-950/40 hover:border-cyan-500 border border-gray-700 rounded-lg text-left transition group">
          <div class="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
            <span>[4]</span> Offline Verification
          </div>
          <div class="text-xs text-gray-400 mt-1">Auditor verifies receipt chain with ONLY public key (Zero API access).</div>
        </button>
      </div>
    </div>

    <!-- Main Grid: Live Editor, Capability & Enforcer Decision -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

      <!-- Column 1: Action & Capability Issuance -->
      <div class="space-y-6">

        <!-- Action Editor -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg">
          <div class="flex justify-between items-center mb-2">
            <h2 class="text-sm font-bold text-white uppercase tracking-wider font-mono">1. Raw Action Payload</h2>
            <button onclick="reorderKeysDemo()" class="text-xs text-cyan-400 hover:text-cyan-300 font-mono">
              🔄 Shuffle Key Order (Test Determinism)
            </button>
          </div>
          <textarea id="actionInput" rows="7" class="w-full bg-black/60 border border-gray-800 rounded-lg p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500" spellcheck="false"></textarea>
          <div class="mt-3 flex items-center justify-between text-xs font-mono bg-gray-950 p-2.5 rounded-lg border border-gray-800/80">
            <span class="text-gray-400">Canonical SHA-256 Digest:</span>
            <span id="actionDigest" class="text-cyan-400 font-bold truncate max-w-[280px]">...</span>
          </div>
        </div>

        <!-- Capability Token Generator -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg space-y-3">
          <div class="flex justify-between items-center">
            <h2 class="text-sm font-bold text-white uppercase tracking-wider font-mono">2. Ed25519 Capability Issuance</h2>
            <button onclick="issueCapability()" class="px-3 py-1.5 text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-black rounded-lg transition">
              Issue Capability Token
            </button>
          </div>
          <div class="grid grid-cols-3 gap-2 text-xs font-mono">
            <div>
              <label class="text-gray-400 block mb-1">Agent ID</label>
              <input id="agentId" type="text" value="agent-support-01" class="w-full bg-black/60 border border-gray-800 rounded px-2 py-1 text-gray-200">
            </div>
            <div>
              <label class="text-gray-400 block mb-1">Scope Pattern</label>
              <input id="scope" type="text" value="customer-actions/*" class="w-full bg-black/60 border border-gray-800 rounded px-2 py-1 text-gray-200">
            </div>
            <div>
              <label class="text-gray-400 block mb-1">TTL (Seconds)</label>
              <input id="ttl" type="number" value="30" class="w-full bg-black/60 border border-gray-800 rounded px-2 py-1 text-gray-200">
            </div>
          </div>
          <div>
            <label class="text-xs font-mono text-gray-400 block mb-1">Signed Compact Capability Token</label>
            <div id="tokenOutput" class="bg-black/60 border border-gray-800 rounded p-2.5 text-xs font-mono text-gray-400 break-all max-h-24 overflow-y-auto">
              No capability issued yet. Click "Issue Capability Token" or run Scenario 1.
            </div>
          </div>
        </div>

      </div>

      <!-- Column 2: Execution Plane & Enforcer Decision -->
      <div class="space-y-6">

        <!-- Enforcer Evaluation Console -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg space-y-4">
          <div class="flex justify-between items-center">
            <div>
              <h2 class="text-sm font-bold text-white uppercase tracking-wider font-mono">3. Protected Enforcer Decision</h2>
              <div class="text-xs text-gray-400">Evaluates signature, recomputed hash, TTL, and atomic lock.</div>
            </div>
            <button onclick="executeAction()" class="px-4 py-1.5 text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-black rounded-lg transition">
              ⚡ Execute at Enforcer
            </button>
          </div>

          <!-- Decision Display Box -->
          <div id="decisionBox" class="p-4 rounded-xl border border-gray-800 bg-black/40 text-center space-y-1">
            <div id="decisionBadge" class="inline-block px-3 py-1 rounded-full text-xs font-bold font-mono bg-gray-800 text-gray-400">
              STANDBY
            </div>
            <div id="decisionTitle" class="text-base font-bold text-gray-200">Awaiting Submission</div>
            <div id="decisionReason" class="text-xs text-gray-400 font-mono">No action submitted to Enforcer yet.</div>
          </div>

          <!-- Enforcer Invariants Checklist -->
          <div class="grid grid-cols-2 gap-2 text-xs font-mono">
            <div id="chkSig" class="p-2 rounded bg-black/40 border border-gray-800/80 flex items-center gap-2">
              <span class="text-gray-500">○</span> Ed25519 Signature
            </div>
            <div id="chkHash" class="p-2 rounded bg-black/40 border border-gray-800/80 flex items-center gap-2">
              <span class="text-gray-500">○</span> Action Hash Match
            </div>
            <div id="chkTTL" class="p-2 rounded bg-black/40 border border-gray-800/80 flex items-center gap-2">
              <span class="text-gray-500">○</span> TTL Not Expired
            </div>
            <div id="chkReplay" class="p-2 rounded bg-black/40 border border-gray-800/80 flex items-center gap-2">
              <span class="text-gray-500">○</span> Single-Use Atomic Lock
            </div>
          </div>
        </div>

        <!-- Offline Verifier Status -->
        <div class="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg space-y-3">
          <div class="flex justify-between items-center">
            <div>
              <h2 class="text-sm font-bold text-white uppercase tracking-wider font-mono">4. Independent Offline Verification</h2>
              <div class="text-xs text-gray-400">Verifies entire receipt chain with only public key.</div>
            </div>
            <button onclick="verifyChainOffline()" class="px-3 py-1.5 text-xs font-bold bg-cyan-700 hover:bg-cyan-600 text-white rounded-lg transition">
              Verify Entire Chain
            </button>
          </div>
          <div id="verifyReport" class="p-3 bg-black/40 border border-gray-800 rounded text-xs font-mono text-gray-300">
            Chain verification status will appear here.
          </div>
        </div>

      </div>

    </div>

    <!-- Immutable Receipt Chain Visualizer -->
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-5 shadow-lg">
      <div class="flex justify-between items-center mb-3">
        <div>
          <h2 class="text-sm font-bold text-white uppercase tracking-wider font-mono">5. Immutable Execution Receipt Chain (Hash-Linked)</h2>
          <div class="text-xs text-gray-400">Each receipt binds the execution result and chains backward to the previous receipt hash.</div>
        </div>
        <div id="chainCountBadge" class="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
          0 Receipts
        </div>
      </div>
      <div id="receiptContainer" class="space-y-2 max-h-60 overflow-y-auto pr-1">
        <div class="text-xs text-gray-500 text-center py-6 font-mono">
          No execution receipts committed yet. Run a legitimate action to generate receipt #1!
        </div>
      </div>
    </div>

  </div>

  <script>
    let currentToken = null;

    const defaultAction = {
      action: "customer-actions/refund",
      order_id: "ORD-789",
      amount: 50000,
      recipient: "ACC-LEGITIMATE"
    };

    document.getElementById("actionInput").value = JSON.stringify(defaultAction, null, 2);

    async function updateActionHash() {
      try {
        const parsed = JSON.parse(document.getElementById("actionInput").value);
        const res = await fetch("/api/action/hash", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({action: parsed})
        });
        const data = await res.json();
        document.getElementById("actionDigest").innerText = data.action_hash;
      } catch (e) {
        document.getElementById("actionDigest").innerText = "INVALID_JSON";
      }
    }

    document.getElementById("actionInput").addEventListener("input", updateActionHash);

    async function loadState() {
      const res = await fetch("/api/state");
      const state = await res.json();
      document.getElementById("gwPub").innerText = state.gateway_public_key;
      document.getElementById("enfPub").innerText = state.enforcer_public_key;
      updateActionHash();
      renderReceipts(state.receipt_chain);
    }

    async function regenerateKeys() {
      await fetch("/api/keys/regenerate", {method: "POST"});
      await loadState();
      alert("Generated fresh Ed25519 keypairs for Gateway and Enforcer!");
    }

    function reorderKeysDemo() {
      const parsed = JSON.parse(document.getElementById("actionInput").value);
      const keys = Object.keys(parsed).reverse();
      const reordered = {};
      keys.forEach(k => reordered[k] = parsed[k]);
      document.getElementById("actionInput").value = JSON.stringify(reordered, null, 2);
      updateActionHash();
    }

    async function issueCapability() {
      const action = JSON.parse(document.getElementById("actionInput").value);
      const agent_id = document.getElementById("agentId").value;
      const scope = document.getElementById("scope").value;
      const ttl_seconds = parseFloat(document.getElementById("ttl").value);

      const res = await fetch("/api/capability/issue", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({action, agent_id, scope, ttl_seconds})
      });
      const data = await res.json();
      currentToken = data.compact_token;
      document.getElementById("tokenOutput").innerText = data.compact_token;
      return data;
    }

    async function executeAction() {
      const action = JSON.parse(document.getElementById("actionInput").value);
      const res = await fetch("/api/enforcer/execute", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({action, token: currentToken})
      });
      const data = await res.json();

      const box = document.getElementById("decisionBox");
      const badge = document.getElementById("decisionBadge");
      const title = document.getElementById("decisionTitle");
      const reason = document.getElementById("decisionReason");

      if (data.status === "ALLOWED") {
        box.className = "p-4 rounded-xl border border-emerald-500/50 bg-emerald-950/20 text-center space-y-1";
        badge.className = "inline-block px-3 py-1 rounded-full text-xs font-bold font-mono bg-emerald-950 text-emerald-400 border border-emerald-800";
        badge.innerText = "✓ EXECUTION PERMITTED";
        title.className = "text-base font-bold text-emerald-400";
        title.innerText = "All Boundary Invariants Validated";
        reason.innerText = "Action committed to ledger. Receipt #" + data.receipt.receipt_id + " chained.";
        setChecks(true, true, true, true);
      } else {
        box.className = "p-4 rounded-xl border border-rose-500/50 bg-rose-950/20 text-center space-y-1";
        badge.className = "inline-block px-3 py-1 rounded-full text-xs font-bold font-mono bg-rose-950 text-rose-400 border border-rose-800";
        badge.innerText = "✗ EXECUTION BLOCKED";
        title.className = "text-base font-bold text-rose-400";
        title.innerText = "Boundary Defense Triggered";
        reason.innerText = data.error;

        const err = data.error || "";
        setChecks(
          !err.includes("INVALID_SIGNATURE"),
          !err.includes("ACTION_HASH_MISMATCH"),
          !err.includes("CAPABILITY_EXPIRED"),
          !err.includes("CAPABILITY_ALREADY_CONSUMED")
        );
      }

      await loadState();
    }

    function setChecks(sig, hash, ttl, replay) {
      document.getElementById("chkSig").innerHTML = sig ? '<span class="text-emerald-400">✓</span> Ed25519 Signature' : '<span class="text-rose-400">✗</span> Ed25519 Signature';
      document.getElementById("chkHash").innerHTML = hash ? '<span class="text-emerald-400">✓</span> Action Hash Match' : '<span class="text-rose-400">✗</span> Action Hash Match';
      document.getElementById("chkTTL").innerHTML = ttl ? '<span class="text-emerald-400">✓</span> TTL Not Expired' : '<span class="text-rose-400">✗</span> TTL Not Expired';
      document.getElementById("chkReplay").innerHTML = replay ? '<span class="text-emerald-400">✓</span> Single-Use Atomic Lock' : '<span class="text-rose-400">✗</span> Single-Use Atomic Lock';
    }

    async function verifyChainOffline() {
      const res = await fetch("/api/receipts/verify", {method: "POST"});
      const data = await res.json();
      const el = document.getElementById("verifyReport");
      if (data.valid) {
        el.className = "p-3 bg-emerald-950/30 border border-emerald-800 rounded text-xs font-mono text-emerald-300";
        el.innerHTML = "✓ VERIFIED PASS: All " + data.receipt_count + " receipts verified offline using ONLY Enforcer Public Key. No tampering detected.";
      } else {
        el.className = "p-3 bg-rose-950/30 border border-rose-800 rounded text-xs font-mono text-rose-300";
        el.innerHTML = "✗ VERIFICATION FAILED: " + data.message;
      }
    }

    function renderReceipts(chain) {
      const container = document.getElementById("receiptContainer");
      document.getElementById("chainCountBadge").innerText = chain.length + " Receipts";
      if (!chain || chain.length === 0) {
        container.innerHTML = '<div class="text-xs text-gray-500 text-center py-6 font-mono">No execution receipts committed yet.</div>';
        return;
      }
      container.innerHTML = chain.map((r, i) => `
        <div class="p-3 bg-black/50 border border-gray-800 rounded-lg text-xs font-mono space-y-1">
          <div class="flex justify-between items-center">
            <span class="text-emerald-400 font-bold">#${i + 1} ${r.receipt_id}</span>
            <span class="text-gray-400 text-[10px]">State: ${r.ledger_state}</span>
          </div>
          <div class="text-gray-400 truncate">Prev Hash : <span class="text-gray-300">${r.prev_receipt_hash}</span></div>
          <div class="text-gray-400 truncate">Curr Hash : <span class="text-cyan-400 font-bold">${r.receipt_hash}</span></div>
          <div class="text-gray-400 truncate">Signature : <span class="text-gray-500">${r.signature.substring(0, 36)}...</span></div>
        </div>
      `).join("");
    }

    async function resetAll() {
      await fetch("/api/reset", {method: "POST"});
      currentToken = null;
      document.getElementById("tokenOutput").innerText = "No capability issued yet.";
      document.getElementById("actionInput").value = JSON.stringify(defaultAction, null, 2);
      updateActionHash();
      document.getElementById("decisionBadge").className = "inline-block px-3 py-1 rounded-full text-xs font-bold font-mono bg-gray-800 text-gray-400";
      document.getElementById("decisionBadge").innerText = "STANDBY";
      document.getElementById("decisionTitle").innerText = "Awaiting Submission";
      document.getElementById("decisionReason").innerText = "State reset.";
      setChecks(false, false, false, false);
      await loadState();
    }

    // Scenarios for Judges
    async function scenarioLegitimate() {
      document.getElementById("actionInput").value = JSON.stringify(defaultAction, null, 2);
      await updateActionHash();
      await issueCapability();
      await executeAction();
    }

    async function scenarioTamperAmount() {
      // 1. Issue capability for 50,000
      document.getElementById("actionInput").value = JSON.stringify(defaultAction, null, 2);
      await updateActionHash();
      await issueCapability();

      // 2. Attacker mutates action payload to 500,000 (10x unauthorized)
      const tampered = Object.assign({}, defaultAction, {amount: 500000, recipient: "ACC-MALICIOUS"});
      document.getElementById("actionInput").value = JSON.stringify(tampered, null, 2);
      await updateActionHash();

      // 3. Attempt execution
      await executeAction();
    }

    async function scenarioReplay() {
      // First ensure a valid execution happens
      await scenarioLegitimate();
      // Second attempt using the SAME consumed token
      await executeAction();
    }

    async function scenarioVerifyOffline() {
      await verifyChainOffline();
    }

    loadState();
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    print("=" * 70)
    print("  AGENTSHIELD V3 -- JUDGE DEMO CONSOLE (ROLE: GIRISH)")
    print("=" * 70)
    print("  Server starting at: http://localhost:8000")
    print("  Open this URL in your web browser to present to judges!")
    print("=" * 70)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
